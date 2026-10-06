require 'net/ssh/loggable'
require 'net/sftp/errors'
require 'net/sftp/resume/checkpoint'
require 'net/sftp/resume/block_verifier'

module Net; module SFTP; module Operations

  # A resumable uploader. Unlike Upload, which always rewrites the whole
  # file, ResumableUpload persists a Checkpoint describing the blocks that
  # have already been written. When a transfer is resumed on a new
  # connection, blocks already present on the server are read back with
  # ordinary SFTP READ requests and their content digests compared with
  # the checkpoint; only blocks that cannot be confirmed are retransmitted.
  #
  # A plain byte offset is never trusted: if the remote file was
  # replaced, truncated, or modified while the connection was down, the
  # affected blocks fail verification and are re-sent. If the remote end
  # changes while verification is in progress (noticed via a changed
  # size or version attributes), the transfer aborts with
  # RemoteChangedError rather than splicing old and new versions together.
  #
  # Example:
  #
  #   sftp.resume_upload!("big.bin", "/remote/big.bin",
  #                       :checkpoint => "big.bin.ckpt")
  #
  # If the connection drops, run the same command again once reconnected.
  #
  # Options:
  #
  # * <tt>:checkpoint</tt> - path of the checkpoint file. Required to
  #   resume a transfer; if omitted for a file path source it defaults to
  #   "<local>.sftp-ckpt". Pass nil for an in-memory (non-resumable
  #   across processes) checkpoint.
  # * <tt>:block_size</tt> - size of each independently verified and
  #   retransmitted block (default 32,000 bytes, like Upload#read_size).
  # * <tt>:requests</tt> - maximum number of in-flight write requests
  #   (default 2).
  # * <tt>:verifier</tt> - an object responding to
  #   <tt>verify(sftp, handle, block, read_size) { |ok, data| ... }</tt>,
  #   used to confirm existing blocks. Defaults to BlockVerifier, which
  #   uses only SFTP READ requests and never runs remote commands.
  # * <tt>:progress</tt> - a block or handler object, as for Upload.
  class ResumableUpload
    include Net::SSH::Loggable
    include Net::SFTP::Constants::StatusCodes

    # The source of the upload on the local host (an IO or a path).
    attr_reader :local

    # The destination path on the remote host.
    attr_reader :remote

    # The hash of options given to the uploader.
    attr_reader :options

    # The SFTP session used by this uploader.
    attr_reader :sftp

    # The Checkpoint describing the transfer.
    attr_reader :checkpoint

    # The path of the checkpoint file, or nil for an ephemeral checkpoint.
    attr_reader :checkpoint_path

    # The ranges that needed (or will need) retransmission after the
    # existing remote data was verified. Empty until verification
    # completes.
    attr_reader :retransmit_ranges

    # A small struct describing the file being uploaded to progress
    # handlers.
    MetaFile = Struct.new(:local, :remote, :size, :handle)

    # The default block size in bytes.
    DEFAULT_BLOCK_SIZE = 32_000

    # The default number of concurrent write requests.
    DEFAULT_REQUESTS = 2

    # Creates and starts a resumable upload on top of +sftp+. The method
    # returns immediately; run the SFTP event loop (or call #wait) to
    # drive the transfer.
    def initialize(sftp, local, remote, options={}, &progress)
      @sftp = sftp
      @local = local
      @remote = remote
      @options = options
      @progress = progress || options[:progress]
      @verifier = options[:verifier] || Resume::BlockVerifier.new
      @retransmit_ranges = []
      @active = 0
      @aborted = false

      self.logger = sftp.logger

      block_size = options[:block_size] || options[:read_size] || DEFAULT_BLOCK_SIZE
      @checkpoint_path =
        options.key?(:checkpoint) ? options[:checkpoint] :
          local.respond_to?(:read) ? nil : "#{local}.sftp-ckpt"

      open_local(local)

      @checkpoint = load_or_build_checkpoint(block_size)

      @active += 1
      request = sftp.stat(remote, &method(:on_stat))
      request[:resume_upload] = self
    end

    # Returns true while the upload has work in flight.
    def active?
      @active > 0
    end

    # Blocks until the upload finishes (or fails).
    def wait
      sftp.loop { active? }
      self
    end

    # Stops the state machine. Outstanding SFTP requests are abandoned.
    def abort!
      @aborted = true
      @active = 0
    end

    private

      def progress; @progress; end

      def open_local(local)
        if local.respond_to?(:read)
          raise ArgumentError, "local IO must be seekable for a resumable upload" unless
            local.respond_to?(:seek)
          @io = local
          @local_name = options[:name] || "<memory>"
        else
          raise ArgumentError, "expected a file to upload" unless ::File.file?(local)
          @io = ::File.open(local, "rb")
          @local_name = local
        end
        @local_size = @io.size
      end

      def load_or_build_checkpoint(block_size)
        if @checkpoint_path && ::File.exist?(@checkpoint_path)
          @checkpoint = Resume::Checkpoint.load(@checkpoint_path)
          validate_checkpoint!(@checkpoint)
          @checkpoint
        else
          @checkpoint = Resume::Checkpoint.new(
            Resume::Checkpoint::UPLOAD, @local_name, remote, @local_size, block_size)
          save_checkpoint!
          @checkpoint
        end
      end

      def validate_checkpoint!(checkpoint)
        if checkpoint.direction != Resume::Checkpoint::UPLOAD
          raise ResumeError,
            "checkpoint describes a #{checkpoint.direction}, not an upload"
        end
        if checkpoint.local != @local_name || checkpoint.remote != remote
          raise ResumeError,
            "checkpoint is for #{checkpoint.local.inspect} -> " +            "#{checkpoint.remote.inspect}, not #{@local_name.inspect} -> #{remote.inspect}"
        end
        if checkpoint.local_size != @local_size
          raise LocalChangedError.new(nil, @local_size, checkpoint.local_size)
        end
      end

      # Called with the STAT response for the remote path.
      def on_stat(response)
        if response.ok?
          @remote_previously_seen = true
          @stat_version = Resume::Checkpoint.version_from_attributes(response[:attrs])
          open_remote("r+")
        elsif response.code == FX_NO_SUCH_FILE
          @remote_previously_seen = false
          @stat_version = nil
          # Nothing at the destination means recorded blocks cannot be
          # confirmed; every block must be sent.
          checkpoint.blocks.each { |block| checkpoint.forget_block(block['offset']) }
          save_checkpoint!
          open_remote("w")
        else
          raise StatusException.new(response, "stat #{remote}")
        end
      end

      def open_remote(flags)
        request = sftp.open(remote, flags, &method(:on_open))
        request[:resume_upload] = self
      end

      def on_open(response)
        unless response.ok?
          raise StatusException.new(response, "open #{remote}")
        end

        @handle = response[:handle]
        @metafile = MetaFile.new(@local_name, remote, @local_size, @handle)
        update_progress(:open, @metafile)

        request = sftp.fstat(@handle, &method(:on_open_fstat))
        request[:resume_upload] = self
      end

      def on_open_fstat(response)
        raise StatusException.new(response, "fstat #{remote}") unless response.ok?
        @baseline_version =
          Resume::Checkpoint.version_from_attributes(response[:attrs]) || @stat_version
        checkpoint.remote_version = @baseline_version
        save_checkpoint!

        if @remote_previously_seen && checkpoint.block_count > 0
          verify_blocks
        else
          plan_retransmission
        end
      end

      # Verifies each recorded block, in offset order, with SFTP READ.
      def verify_blocks
        @blocks_to_verify = checkpoint.blocks.dup
        verify_next_block
      end

      def verify_next_block
        if (block = @blocks_to_verify.shift).nil?
          recheck_remote_version
        else
          @verifier.verify(sftp, @handle, block, options[:verify_read_size]) do |ok, data|
            update_progress(:verify, block, ok, data)
            checkpoint.forget_block(block['offset']) unless ok
            verify_next_block
          end
        end
      end

      # Re-stats the open file once verification is complete. A changed
      # size (or other identifying attributes) means the file was replaced
      # concurrently; the transfer must stop.
      def recheck_remote_version
        request = sftp.fstat(@handle, &method(:on_verify_fstat))
        request[:resume_upload] = self
      end

      def on_verify_fstat(response)
        raise StatusException.new(response, "fstat #{remote}") unless response.ok?
        current = Resume::Checkpoint.version_from_attributes(response[:attrs])
        if remote_version_changed?(@baseline_version, current)
          raise RemoteChangedError.new(nil, @baseline_version, current)
        end
        plan_retransmission
      end

      def remote_version_changed?(before, after)
        return false if before.nil? || after.nil?
        VERSION_MARKERS.any? { |key| before.key?(key) && after.key?(key) && before[key] != after[key] }
      end

      # Attributes that identify a remote file version. Access time is
      # deliberately excluded because reading the file can update it.
      VERSION_MARKERS = %w(size uid gid permissions mtime type).freeze

      def plan_retransmission
        @retransmit_ranges = checkpoint.missing_ranges
        update_progress(:retransmit, @metafile, @retransmit_ranges, checkpoint)
        write_blocks
      end

      # Sends unconfirmed blocks, up to :requests concurrent writes.
      def write_blocks
        @pending_writes = 0
        @write_queue = checkpoint.each_block.select { |offset, _| !checkpoint.block?(offset) }
        @write_queue.map! { |offset, length| { 'offset' => offset, 'length' => length } }

        limit = (options[:requests] || DEFAULT_REQUESTS).to_i
        limit.times { send_next_write }
        finish_writes_if_idle
      end

      def send_next_write
        return if @aborted
        block = @write_queue.shift
        return unless block

        @io.seek(block['offset'])
        data = @io.read(block['length'])

        @pending_writes += 1
        update_progress(:put, @metafile, block['offset'], data)
        request = sftp.write(@handle, block['offset'], data, &method(:on_write))
        request[:resume_upload] = self
        request[:resume_block] = block
        request[:resume_data] = data
      end

      def on_write(response)
        @pending_writes -= 1
        block = response.request[:resume_block]
        data = response.request[:resume_data]
        unless response.ok?
          raise StatusException.new(response, "write #{remote} @#{block['offset']}")
        end

        # The block is recorded only after the server acknowledges the
        # write, and the checkpoint is flushed before any further progress.
        checkpoint.record_block(block['offset'], block['length'],
                                Resume::Checkpoint.digest(data))
        checkpoint.remote_version = nil
        save_checkpoint!
        update_progress(:written, @metafile, block['offset'], data)

        send_next_write
        finish_writes_if_idle
      end

      def finish_writes_if_idle
        return unless @pending_writes.zero? && @write_queue.empty?
        truncate_if_needed
      end

      # If the remote file held extra bytes beyond the local source
      # (e.g. the new source's last block is shorter), shrink it before
      # closing.
      def truncate_if_needed
        remote_size = @baseline_version && @baseline_version['size']
        if remote_size && remote_size > @local_size
          request = sftp.fsetstat(@handle, :size => @local_size, &method(:on_truncate))
          request[:resume_upload] = self
        else
          close_remote
        end
      end

      def on_truncate(response)
        raise StatusException.new(response, "fsetstat #{remote}") unless response.ok?
        close_remote
      end

      def close_remote
        request = sftp.close(@handle, &method(:on_close))
        request[:resume_upload] = self
      end

      def on_close(response)
        raise StatusException.new(response, "close #{remote}") unless response.ok?
        @io.close unless local.respond_to?(:read) && @io.equal?(local)
        update_progress(:close, @metafile)

        # Only after every write (and the final close) has been
        # acknowledged do we remove the checkpoint and signal completion.
        Resume::Checkpoint.delete(@checkpoint_path) if @checkpoint_path
        @active -= 1
        update_progress(:finish, self)
      end

      def save_checkpoint!
        checkpoint.save(@checkpoint_path) if @checkpoint_path
      end

      def update_progress(event, *args)
        callback = "on_#{event}"
        if progress.respond_to?(callback)
          progress.send(callback, self, *args)
        elsif progress.respond_to?(:call)
          progress.call(event, self, *args)
        end
      end
  end

end; end; end
