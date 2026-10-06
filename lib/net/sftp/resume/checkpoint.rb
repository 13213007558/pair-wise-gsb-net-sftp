require 'json'
require 'digest'
require 'tempfile'
require 'fileutils'
require 'net/sftp/errors'

module Net; module SFTP; module Resume

  # A Checkpoint records the state of a resumable transfer so that it can
  # be continued on a later connection. It deliberately records enough
  # information to validate the bytes already present at the destination
  # rather than trusting a plain byte offset:
  #
  # * <b>direction</b> - <tt>:upload</tt> or <tt>:download</tt>, so a
  #   checkpoint can never be applied to a transfer running the other way.
  # * <b>source/destination identity</b> - the local and remote paths and
  #   the size of the local source.
  # * <b>block geometry</b> - the read/write block size used by the
  #   transfer.
  # * <b>completed blocks</b> - any number of disjoint, already written
  #   byte ranges. Every block carries its offset, length and a digest of
  #   its exact contents, allowing the destination to be verified with
  #   ordinary SFTP READ requests before the block is skipped.
  # * <b>remote version</b> - the destination attributes that could be
  #   obtained (size, mtime, permissions, and so on), so that a swapped or
  #   replaced remote file can be noticed.
  #
  # Checkpoints are serialized as JSON. The format carries a version tag
  # and a SHA-256 fingerprint of its payload; a tampered or truncated file
  # raises CheckpointCorruptError instead of being used to resume.
  class Checkpoint

    # The on-disk format version implemented by this class.
    FORMAT_VERSION = 1

    # The digest algorithm used to summarize block contents and to
    # fingerprint the serialized checkpoint.
    DIGEST_ALGORITHM = 'sha256'.freeze

    # Transfer direction for checkpoints describing an upload.
    UPLOAD = 'upload'.freeze

    # Transfer direction for checkpoints describing a download.
    DOWNLOAD = 'download'.freeze

    # The transfer direction, as a string ("upload" or "download").
    attr_accessor :direction

    # The path (or reported name) of the local end of the transfer.
    attr_accessor :local

    # The path of the remote end of the transfer.
    attr_accessor :remote

    # The size, in bytes, of the local source at the time the checkpoint
    # was written.
    attr_accessor :local_size

    # The block size used to divide the transfer, in bytes.
    attr_accessor :block_size

    # A hash of the remote version attributes most recently observed, or
    # nil if none could be obtained.
    attr_accessor :remote_version

    # Builds a fresh checkpoint for an :upload or :download transfer.
    def initialize(direction, local, remote, local_size, block_size)
      @direction = validate_direction(direction)
      @local = local
      @remote = remote
      @local_size = Integer(local_size)
      @block_size = Integer(block_size)
      @blocks = {}
      @remote_version = nil
    end

    # Records that the block beginning at +offset+ and spanning +length+
    # bytes, whose contents hash to +digest+, is present at the
    # destination. Recording a block twice with identical data is a
    # no-op; recording a conflicting length for the same offset removes
    # the block so that it is retransmitted.
    def record_block(offset, length, digest)
      offset = Integer(offset)
      length = Integer(length)
      record = { 'offset' => offset, 'length' => length,
                 'digest' => String(digest).downcase }
      if (existing = @blocks[offset]) && existing['length'] != length
        @blocks.delete(offset)
      else
        @blocks[offset] = record
      end
    end

    # Removes the block record beginning at +offset+, if any. This is used
    # when verification shows that the destination no longer holds the
    # expected bytes for that block.
    def forget_block(offset)
      @blocks.delete(Integer(offset))
    end

    # Returns true if a block beginning at +offset+ is recorded.
    def block?(offset)
      @blocks.key?(Integer(offset))
    end

    # Returns the recorded block (a hash of 'offset', 'length', and
    # 'digest') beginning at +offset+, or nil if no such block is
    # recorded.
    def block(offset)
      @blocks[Integer(offset)]
    end

    # Returns the recorded blocks as an array of hashes, ordered by
    # offset.
    def blocks
      @blocks.values.sort_by { |entry| entry['offset'] }
    end

    # The number of completed blocks recorded in the checkpoint.
    def block_count
      @blocks.size
    end

    # Enumerates every fixed-size block of the local source as
    # [offset, length] pairs.
    def each_block
      return enum_for(:each_block) unless block_given?
      offset = 0
      remaining = local_size
      while remaining > 0
        length = remaining < block_size ? remaining : block_size
        yield offset, length
        offset += length
        remaining -= length
      end
      nil
    end

    # Merges adjacent verified blocks into a sorted list of completed,
    # half-open byte ranges, each given as [offset, end_offset].
    # Disjoint verified areas stay separate, so several finished intervals
    # may be returned.
    def completed_intervals
      intervals = []
      each_block do |offset, expected_length|
        block = @blocks[offset]
        next unless block && block['length'] == expected_length
        if (last = intervals.last) && last[1] == offset
          last[1] = offset + expected_length
        else
          intervals << [offset, offset + expected_length]
        end
      end
      intervals
    end

    # Returns the half-open byte ranges [offset, end_offset] that still
    # have to be transferred. The complement of #completed_intervals,
    # adjacent gaps are merged so a caller receives the concrete ranges to
    # retransmit rather than a single length-based resume offset.
    def missing_ranges
      done = completed_intervals
      missing = []
      cursor = 0
      done.each do |offset, end_offset|
        missing << [cursor, offset] if cursor < offset
        cursor = end_offset
      end
      missing << [cursor, local_size] if cursor < local_size
      missing
    end

    # Serializes the checkpoint to a JSON string, including its payload
    # fingerprint.
    def to_json(*args)
      payload = {
        'format' => FORMAT_VERSION,
        'direction' => direction,
        'local' => local,
        'remote' => remote,
        'local_size' => local_size,
        'block_size' => block_size,
        'remote_version' => remote_version,
        'blocks' => blocks
      }
      document = {
        'payload' => payload,
        'digest' => self.class.digest_json(payload)
      }
      JSON.generate(document, *args)
    end

    # Atomically writes the checkpoint to +path+ (via a temporary file and
    # rename), so a crash can never leave a half-written checkpoint behind.
    def save(path)
      path = String(path)
      directory = ::File.dirname(path)
      unless directory.empty? || ::File.directory?(directory)
        FileUtils.mkdir_p(directory)
      end
      Tempfile.open(::File.basename(path), directory) do |tempfile|
        tempfile.binmode
        tempfile.write(to_json)
        tempfile.flush
        tempfile.fsync rescue nil
        tempfile.close
        FileUtils.chmod(0o600, tempfile.path)
        FileUtils.mv(tempfile.path, path)
      end
      path
    end

    # Deletes the checkpoint at +path+ if it exists.
    def self.delete(path)
      ::File.delete(path) if ::File.exist?(path)
    end

    # Loads and validates a checkpoint from +path+. Raises
    # CheckpointCorruptError if the file is missing fields, uses an
    # unknown format, or its payload does not match its fingerprint.
    def self.load(path)
      data = begin
        ::File.read(path)
      rescue SystemCallError => error
        raise CheckpointCorruptError.new("unable to read checkpoint", path, error)
      end
      parse(data, path)
    end

    # Builds a checkpoint from a JSON +string+ previously produced by
    # #to_json. +path+ is used only to annotate errors.
    def self.parse(string, path=nil)
      document = begin
        JSON.parse(String(string))
      rescue JSON::ParserError => error
        raise CheckpointCorruptError.new("checkpoint is not valid JSON", path, error)
      end

      payload = document.is_a?(Hash) ? document['payload'] : nil
      unless payload.is_a?(Hash)
        raise CheckpointCorruptError.new("checkpoint is missing its payload", path)
      end

      unless payload['format'].is_a?(Integer) && payload['format'] == FORMAT_VERSION
        raise CheckpointCorruptError.new(
          "unsupported checkpoint format #{payload['format'].inspect}", path)
      end

      fingerprint = document['digest']
      unless fingerprint.is_a?(String) && fingerprint == digest_json(payload)
        raise CheckpointCorruptError.new("checkpoint digest mismatch", path)
      end

      checkpoint = begin
        new(payload['direction'], payload['local'], payload['remote'],
            payload['local_size'], payload['block_size'])
      rescue ArgumentError, TypeError, ResumeError => error
        raise CheckpointCorruptError.new("checkpoint has invalid fields", path, error)
      end
      checkpoint.remote_version = payload['remote_version']

      raw_blocks = payload['blocks']
      unless raw_blocks.is_a?(Array)
        raise CheckpointCorruptError.new("checkpoint has invalid blocks", path)
      end
      raw_blocks.each do |block|
        unless block.is_a?(Hash) && block['offset'].is_a?(Integer) &&
               block['length'].is_a?(Integer) && block['digest'].is_a?(String)
          raise CheckpointCorruptError.new("checkpoint has an invalid block", path)
        end
        checkpoint.record_block(block['offset'], block['length'], block['digest'])
      end
      checkpoint
    end

    # Returns the lower-case hex SHA-256 digest of +data+.
    def self.digest(data)
      Digest::SHA256.hexdigest(data || ''.b).downcase
    end

    # Fingerprints a payload hash in its canonical serialized form.
    def self.digest_json(payload)
      digest(JSON.generate(payload))
    end

    # Extracts the portable subset of an SFTP attributes object (such as
    # Net::SFTP::Protocol::V01::Attributes) for storage as remote version
    # information. Returns nil if +attrs+ is nil.
    def self.version_from_attributes(attrs)
      return nil unless attrs
      version = {}
      %w(size uid gid permissions atime mtime type).each do |name|
        value = attribute_value(attrs, name.to_sym)
        version[name] = value unless value.nil?
      end
      extended = attribute_value(attrs, :extended)
      if extended.is_a?(Hash) && !extended.empty?
        version['extended'] = extended
      end
      version.freeze
    end

    private

      # Reads +name+ from an attributes-like object. Structs (used in
      # tests) expose every symbol as a reader, so they are indexed;
      # protocol Attributes objects are read via their accessors.
      def self.attribute_value(attrs, name)
        if attrs.respond_to?(:members)
          attrs[name]
        elsif attrs.respond_to?(name)
          attrs.public_send(name)
        end
      end
      private_class_method :attribute_value

    def validate_direction(direction)
      case direction.to_s
      when UPLOAD then UPLOAD
      when DOWNLOAD then DOWNLOAD
      else
        raise ArgumentError,
          "unsupported transfer direction #{direction.inspect} (expected :upload or :download)"
      end
    end
  end

end; end; end
