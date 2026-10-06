require 'digest'
require 'net/ssh/loggable'
require 'net/sftp/errors'
require 'net/sftp/operations/resumable_checkpoint'

module Net; module SFTP; module Operations

  # A resumable uploader.
  #
  # Unlike Net::SFTP::Operations::Upload, this never assumes that the bytes
  # already present on the server are valid just because of their length. The
  # transfer is split into fixed-size blocks; when a checkpoint exists, every
  # block it claims is read back from the server with an ordinary SFTP READ
  # request and its digest compared with the local content. Only blocks that
  # match are skipped; everything else is re-sent. The two sets may be
  # interleaved, so any number of discrete "holes" is supported.
  #
  # Before verification starts the server's version information for the
  # remote file (size, mtime and any other attributes it reports) is
  # snapshotted. The snapshot is taken again before every verification READ;
  # if the file changed in between (it was replaced during the outage), the
  # upload aborts with Net::SFTP::RemoteChangedError before any WRITE, so
  # data from two different remote versions can never be spliced together.
  #
  # No checksum extension is required: when the server does not implement
  # one, verification still works through SFTP READ. No remote shell command
  # is ever executed.
  #
  # Options (in addition to those understood by Upload):
  #
  # * <tt>:block_size</tt> - verification block size in bytes (default
  #   32,000). The checkpoint must have been written with the same value.
  # * <tt>:checkpoint</tt> - path of the checkpoint file. A checkpoint is
  #   written after the initial verification and after every confirmed
  #   block.
  # * <tt>:restart</tt> - when true, an existing checkpoint is ignored and
  #   the whole file is uploaded from the start. Without it, an unreadable,
  #   tampered or semantically incompatible checkpoint raises
  #   Net::SFTP::CheckpointCorruptError instead of silently restarting.
  # * <tt>:progress</tt> - progress callback/handler, as for Upload.
  #
  # Progress events (in order):
  #
  # * <tt>:open</tt>     - metadata for the file being uploaded
  # * <tt>:verify</tt>   - +(metadata, offset, length, matched)+ for each
  #   existing block checked via READ
  # * <tt>:resume</tt>   - +(metadata, pending_ranges)+ after verification:
  #   the byte ranges ([offset, length] pairs) that must be re-sent
  # * <tt>:put</tt>      - +(metadata, offset, data)+ for every WRITE
  # * <tt>:close</tt>   - metadata, after the final CLOSE succeeds
  # * <tt>:finish</tt>  - once, and only after all target blocks have
  #   received their WRITE confirmation and the CLOSE has been acknowledged
  class ResumableUpload
    include Net::SSH::Loggable

    DEFAULT_BLOCK_SIZE = 32_000

    attr_reader :local
    attr_reader :remote
    attr_reader :options
    attr_reader :sftp
    attr_reader :properties
    attr_reader :checkpoint

    # Metadata describing the file being transferred, handed to progress
    # callbacks.
    Meta = Struct.new(:local, :remote, :size, :block_size, :handle)

    def initialize(sftp, local, remote, options={}, &progress) #:nodoc:
      @sftp = sftp
      @local = local
      @remote = remote
      @options = options
      @progress = progress || options[:progress]
      @properties = options[:properties] || {}
      @block_size = (options[:block_size] || DEFAULT_BLOCK_SIZE).to_i
      raise ArgumentError, "block_size must be positive" unless @block_size > 0
      self.logger = sftp.logger

      @running = true
      @local_name, @io = open_source(local)
      @digests, @source_digest, @size = digest_source(@io)

      @checkpoint = load_or_create_checkpoint

      @verify_queue = []
      @write_queue  = []
      @handle = nil
      @meta = Meta.new(@local_name, remote, @size, @block_size, nil)

      update_progress(:open, @meta)

      sftp.stat(remote, &method(:on_initial_stat))
    end

    def active?
      @running
    end

    def abort!
      @running = false
      self
    end

    def wait
      sftp.loop { active? }
      self
    end

    def [](name); @properties[name.to_sym]; end
    def []=(name, value); @properties[name.to_sym] = value; end

    private

      def progress; @progress; end

      def open_source(local)
        if local.respond_to?(:read)
          unless local.respond_to?(:seek) && local.respond_to?(:pos=)
            raise ArgumentError, "resumable upload needs a seekable IO (got #{local.class})"
          end
          [options[:name] || "<memory>", local]
        else
          [local, ::File.open(local, "rb")]
        end
      end

      # Reads the source once, block by block, recording the per-block digest
      # and the digest of the whole stream.
      def digest_source(io)
        io.pos = 0
        overall = Digest::SHA256.new
        digests = {}
        index = 0
        total = 0
        while (chunk = io.read(@block_size))
          overall.update(chunk)
          digests[index] = Digest::SHA256.hexdigest(chunk)
          total += chunk.bytesize
          index += 1
        end
        io.pos = 0
        [digests, overall.hexdigest, total]
      end

      def load_or_create_checkpoint
        fresh = Proc.new do
          ResumableCheckpoint.create(
            :local => @local_name, :remote => remote,
            :block_size => @block_size, :total_size => @size,
            :source_digest => @source_digest)
        end

        return fresh.call if options[:restart]

        path = checkpoint_path
        return fresh.call unless path && ::File.exist?(path)

        cp = ResumableCheckpoint.load_file(path)
        unless cp.direction == "upload" && cp.local == @local_name &&
               cp.remote == remote && cp.block_size == @block_size &&
               cp.source_digest == @source_digest
          raise CheckpointCorruptError.new(
            "checkpoint does not describe this local file", path)
        end
        cp
      end

      def checkpoint_path
        path = options[:checkpoint]
        path = path.to_path if path.respond_to?(:to_path)
        path
      end

      def save_checkpoint!
        path = checkpoint_path
        if path
          @checkpoint.refresh_ranges!
          @checkpoint.save(path)
        end
      end

      # First contact with the remote: does the target exist, and what does
      # the server currently report about it?
      def on_initial_stat(response)
        if response.ok?
          @baseline_version = version_from_attrs(response[:attrs])
          # An existing file is opened read/write without truncation so that
          # verification READs work; it is shrunk explicitly afterwards if the
          # new content is shorter.
          sftp.open(remote, "r+", &method(:on_open))
        elsif response.code == Net::SFTP::Constants::StatusCodes::FX_NO_SUCH_FILE
          @baseline_version = nil
          sftp.open(remote, "w", &method(:on_open))
        else
          fail_with_status(response, "stat #{remote}")
        end
      end

      def on_open(response)
        fail_with_status(response, "open #{remote}") unless response.ok?
        @handle = response[:handle]
        @meta.handle = @handle
        # Everything the checkpoint claims is suspect until READ-verified.
        @verify_queue = @checkpoint.verified_indexes
        verify_next_block
      end

      # Drives verification. Candidate blocks come from the checkpoint only:
      # the local length never decides what may be skipped.
      def verify_next_block
        unless @verify_queue.empty?
          index = @verify_queue.first

          # Re-observe the remote version immediately before every READ. A
          # change here means the file was replaced mid-verification.
          sftp.stat(remote) do |response|
            fail_with_status(response, "stat #{remote}") unless response.ok?
            current = version_from_attrs(response[:attrs])
            if @baseline_version && current != @baseline_version
              abort_with_remote_change(current)
            else
              offset = @checkpoint.offset_of(index)
              length = @checkpoint.size_of(index)
              sftp.read(@handle, offset, length, &method(:on_verify_read))
            end
          end
          return
        end

        begin_writing
      end

      def on_verify_read(response)
        index = @verify_queue.shift
        length = @checkpoint.size_of(index)

        if response.eof?
          finish_verify_block(index, false, length)
        elsif !response.ok?
          fail_with_status(response, "read #{remote} @#{@checkpoint.offset_of(index)}")
        else
          # The READ raced with an out-of-band replacement; re-observe the
          # version before trusting the returned bytes.
          sftp.stat(remote) do |stat_response|
            fail_with_status(stat_response, "stat #{remote}") unless stat_response.ok?
            current = version_from_attrs(stat_response[:attrs])
            if @baseline_version && current != @baseline_version
              abort_with_remote_change(current)
            else
              remote_data = response[:data]
              remote_digest = Digest::SHA256.hexdigest(remote_data)
              # A short read is a mismatch even if the leading bytes happen
              # to agree.
              matched = remote_data.bytesize == length &&
                        remote_digest == @checkpoint.digest_for(index) &&
                        remote_digest == @digests[index]
              finish_verify_block(index, matched, length)
            end
          end
        end
      end

      def finish_verify_block(index, matched, length)
        @checkpoint.unmark(index) unless matched
        update_progress(:verify, @meta, @checkpoint.offset_of(index), length, matched)
        verify_next_block
      end

      def begin_writing
        total = @checkpoint.block_count
        @write_queue = (0...total).reject { |i| @checkpoint.verified?(i) }
        @pending_ranges = @checkpoint.pending_ranges

        @checkpoint.remote_version = @baseline_version
        save_checkpoint!
        update_progress(:resume, @meta, @pending_ranges)

        shrink_remote_if_needed
      end

      # The server may hold a longer file from the previous (different) local
      # content. Truncate to the final size before writing the last block so
      # no stale tail can survive.
      def shrink_remote_if_needed
        remote_size = @baseline_version && @baseline_version[:size]
        if remote_size && remote_size > @size
          sftp.setstat(remote, :size => @size, &method(:on_shrink))
        else
          write_next_block
        end
      end

      def on_shrink(response)
        fail_with_status(response, "setstat #{remote}") unless response.ok?
        write_next_block
      end

      def write_next_block
        if @write_queue.empty?
          update_progress(:close, @meta)
          sftp.close(@handle, &method(:on_close))
          return
        end

        index = @write_queue.first
        offset = @checkpoint.offset_of(index)
        @io.pos = offset
        data = @io.read(@checkpoint.size_of(index))

        update_progress(:put, @meta, offset, data)
        sftp.write(@handle, offset, data, &method(:on_write))
      end

      def on_write(response)
        fail_with_status(response, "write #{remote}") unless response.ok?
        index = @write_queue.shift
        @checkpoint.mark(index, @digests[index])
        @checkpoint.remote_version = @baseline_version
        save_checkpoint!
        write_next_block
      end

      def on_close(response)
        fail_with_status(response, "close #{remote}") unless response.ok?
        begin
          @io.close unless local.respond_to?(:read)
        rescue SystemCallError
          # closing a local file must not mask a completed remote transfer
        end
        @running = false
        # finish is strictly after every target block's WRITE confirmation
        # and the CLOSE acknowledgement.
        update_progress(:finish, @meta)
      end

      def abort_with_remote_change(current)
        @running = false
        raise RemoteChangedError.new(remote, @baseline_version, current)
      end

      def fail_with_status(response, text)
        @running = false
        raise StatusException.new(response, text)
      end

      # Extracts whatever version information the server can give. Values are
      # all plain JSON-able types so the snapshot can live in the checkpoint.
      def version_from_attrs(attrs)
        return nil unless attrs
        snapshot = {}
        %w(size uid gid permissions atime mtime).each do |name|
          value = attrs.send(name) rescue nil
          snapshot[name.to_sym] = value unless value.nil?
        end
        if attrs.respond_to?(:extended) && attrs.extended.is_a?(Hash)
          snapshot[:extended] = Hash[attrs.extended.map { |k, v| [k.to_s, v.to_s] }]
        end
        snapshot
      end

      def update_progress(event, *args)
        on = "on_#{event}"
        if progress.respond_to?(on)
          progress.send(on, self, *args)
        elsif progress.respond_to?(:call)
          progress.call(event, self, *args)
        end
      end
  end

end; end; end
