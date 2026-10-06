require 'json'
require 'digest'

module Net; module SFTP; module Operations

  # Persistent state for a single resumable upload.
  #
  # A checkpoint never claims that a byte range is present on the server by
  # local length alone. Every completed range is stored as a sequence of
  # fixed-size blocks, and each block carries a digest of the data that was
  # (independently) confirmed at that offset. On reconnect, the caller reads
  # those blocks back from the server and skips a block only when its digest
  # matches the checkpoint.
  #
  # The checkpoint records:
  #
  # * +direction+:: always "upload" (the format is reserved for downloads
  #   as well).
  # * +local+/+remote+:: the two endpoints of the transfer.
  # * +block_size+:: the verification block size in bytes.
  # * +total_size+:: the size in bytes of the local source.
  # * +source_digest+:: digest of the complete local source, computed while
  #   the blocks were written. A resumed transfer is valid only for the same
  #   local content.
  # * +blocks+:: a sparse map of block index to the digest of the data
  #   confirmed at that block, allowing multiple discrete completed ranges.
  # * +ranges+:: a compact, human-readable list of completed byte intervals,
  #   each given as [offset, length]. It is derived from +blocks+ when the
  #   checkpoint is written and may contain multiple discrete entries.
  # * +remote_version+:: whatever version information the server could give
  #   (size, mtime, checksum extension replies, ...) at the time the blocks
  #   were confirmed.
  #
  # On disk the checkpoint is JSON wrapped in an outer envelope that carries
  # a SHA-256 HMAC of the payload. A tampered or truncated file fails the
  # envelope check and is rejected with Net::SFTP::CheckpointCorruptError
  # rather than silently treated as "no progress".
  class ResumableCheckpoint

    FORMAT_VERSION = 1
    DIGEST_ALGORITHM = "sha256"

    # Raised when code asks for a block that does not exist in the source.
    class RangeError < ArgumentError; end

    # The sparse map of verified block indexes to block digests. The map is
    # the single source of truth for "what may possibly be skipped"; it can
    # represent any number of discrete completed intervals.
    attr_reader :blocks

    # Builds a fresh checkpoint for an upload of +local+ to +remote+. The
    # block size defaults to the read size of the uploader.
    def self.create(local:, remote:, block_size:, total_size:, source_digest:)
      payload = {
        "format_version" => FORMAT_VERSION,
        "direction"      => "upload",
        "local"          => local,
        "remote"         => remote,
        "block_size"     => block_size.to_i,
        "total_size"     => total_size.to_i,
        "source_digest"  => source_digest,
        "digest_algo"    => DIGEST_ALGORITHM,
        "blocks"         => {},
        "ranges"         => [],
        "remote_version" => nil
      }
      new(payload)
    end

    # Loads a checkpoint from a JSON document. +path+ is used only for error
    # messages and may be nil when the JSON was supplied directly (e.g. by an
    # application managing its own storage).
    #
    # Raises Net::SFTP::CheckpointCorruptError for any structural problem,
    # failed integrity check, unsupported format version, or semantic mismatch
    # with the requested transfer. Callers that want to treat a corrupt
    # checkpoint as a fresh start must do so explicitly.
    def self.load(json, path=nil)
      envelope =
        begin
          data = JSON.parse(json)
          data.is_a?(Hash) ? data : nil
        rescue JSON::ParserError
          nil
        end

      raise CheckpointCorruptError.new("not a JSON object", path) unless envelope

      payload = envelope["payload"]
      mac     = envelope["mac"]
      unless payload.is_a?(Hash) && mac.is_a?(String)
        raise CheckpointCorruptError.new("missing payload or mac", path)
      end

      expected = envelope_mac(canonical_json(payload))
      unless secure_equal?(expected, mac)
        raise CheckpointCorruptError.new("integrity check failed", path)
      end

      checkpoint = new(payload, path)
      checkpoint.normalize_block_keys!
      checkpoint.send(:validate!)
      checkpoint
    rescue CheckpointCorruptError
      raise
    end

    # Loads a checkpoint from +path+. See ::load for the failure modes.
    def self.load_file(path)
      load(::File.binread(path), path)
    rescue SystemCallError => e
      raise CheckpointCorruptError.new("unreadable: #{e.message}", path)
    end

    # Constant-time comparison so that a flipped bit in the mac cannot be
    # found faster through timing.
    def self.secure_equal?(a, b)
      return false unless a.bytesize == b.bytesize
      l = a.unpack("C#{a.bytesize}")
      r = 0
      b.each_byte { |byte| r |= byte ^ l.shift }
      r == 0
    end

    # JSON key order must not affect the mac, so the payload is serialized
    # canonically before hashing.
    def self.canonical_json(payload)
      JSON.generate(payload)
    end

    def self.envelope_mac(canonical)
      Digest::SHA256.hexdigest(canonical)
    end

    def initialize(payload, path=nil, validate: false) #:nodoc:
      @path = path
      @payload = payload
      @blocks = payload["blocks"]
      validate! if validate
    end

    # JSON only knows string keys; converts the sparse block map back to
    # integer indexes after loading.
    def normalize_block_keys!
      normalized = {}
      @blocks.each do |index, digest|
        key = index.is_a?(Integer) ? index : Integer(index, exception: false)
        raise CheckpointCorruptError.new("block index #{index.inspect} is not an integer", @path) if key.nil?
        normalized[key] = digest
      end
      @payload["blocks"] = normalized
      @blocks = normalized
      self
    end

    #-- direction / endpoints --

    def direction;      @payload["direction"];      end
    def local;          @payload["local"];          end
    def remote;         @payload["remote"];         end
    def block_size;     @payload["block_size"];     end
    def total_size;     @payload["total_size"];     end
    def source_digest;  @payload["source_digest"];  end
    def digest_algo;    @payload["digest_algo"] || DIGEST_ALGORITHM; end

    # Version information captured from the server (a hash). May be nil when
    # the server reports nothing usable.
    def remote_version
      version = @payload["remote_version"]
      return nil unless version
      symbolized = {}
      version.each do |key, value|
        value = Hash[value.map { |k, v| [k.to_sym, v] }] if value.is_a?(Hash)
        symbolized[key.to_sym] = value
      end
      symbolized
    end

    def remote_version=(version)
      @payload["remote_version"] = version
    end

    # Completed byte intervals as recorded in the checkpoint payload
    # ([offset, length] pairs). This is the block-range view that is
    # persisted; #completed_intervals gives the live view computed from
    # #blocks.
    def recorded_ranges
      @payload["ranges"] ||= []
    end

    # Recomputes the recorded byte intervals from the current set of
    # verified blocks. Called before persisting the checkpoint.
    def refresh_ranges!
      @payload["ranges"] = completed_intervals.map do |start_index, end_index|
        start_off = offset_of(start_index)
        end_off   = offset_of(end_index) + size_of(end_index)
        [start_off, end_off - start_off]
      end
      self
    end

    # Number of blocks the local source is made of.
    def block_count
      return 0 if block_size.to_i <= 0 || total_size.to_i <= 0
      (total_size + block_size - 1) / block_size
    end

    # Byte offset at which the given block starts.
    def offset_of(index)
      index * block_size
    end

    # Number of bytes block +index+ contributes to the source; the final
    # block may be shorter than #block_size.
    def size_of(index)
      ensure_block!(index)
      start = offset_of(index)
      [block_size, total_size - start].min
    end

    # Digest recorded for block +index+, or nil when the block has never been
    # confirmed.
    def digest_for(index)
      @blocks[index]
    end

    def verified?(index)
      @blocks.key?(index)
    end

    # Marks block +index+ as confirmed with the given digest.
    def mark(index, digest)
      ensure_block!(index)
      @blocks[index] = digest
    end

    # Removes the record for block +index+ (used when verification shows that
    # the server's content at that offset differs from the checkpoint).
    def unmark(index)
      @blocks.delete(index)
    end

    # Sorted list of completed block indexes; holes are preserved.
    def verified_indexes
      @blocks.keys.sort
    end

    # Compact list of [start_index, end_index] intervals of completed blocks.
    # Multiple discrete intervals are returned separately.
    def completed_intervals
      intervals = []
      start = finish = nil
      verified_indexes.each do |index|
        if start.nil?
          start = finish = index
        elsif index == finish + 1
          finish = index
        else
          intervals << [start, finish]
          start = finish = index
        end
      end
      intervals << [start, finish] if start
      intervals
    end

    # Byte ranges ([offset, length]) that still have to be transferred. Holes
    # in the middle of the file are reported as separate ranges, and the last
    # range is shortened when the final block is partial.
    def pending_ranges
      ranges = []
      hole_start = nil
      (0...block_count).each do |index|
        # The final block may be shorter than block_size, so its end is the
        # total size, not offset_of(index) + block_size.
        if verified?(index)
          if hole_start
            start_off = offset_of(hole_start)
            end_off = [offset_of(index), total_size].min
            ranges << [start_off, end_off - start_off]
            hole_start = nil
          end
        else
          hole_start = index unless hole_start
        end
      end
      if hole_start
        start_off = offset_of(hole_start)
        ranges << [start_off, total_size - start_off]
      end
      ranges
    end

    # Fraction of the source covered by confirmed blocks (0.0..1.0).
    def completed_fraction
      return 1.0 if total_size.to_i <= 0
      bytes = verified_indexes.sum { |index| size_of(index) }
      bytes.to_f / total_size
    end

    def complete?
      @blocks.length == block_count && block_count > 0
    end

    # Serializes the checkpoint, including its integrity envelope.
    def to_json(*)
      canonical = self.class.canonical_json(@payload)
      JSON.generate("payload" => @payload, "mac" => self.class.envelope_mac(canonical))
    end

    # Persists the checkpoint to +path+ atomically (write to a temporary
    # file in the same directory, then rename), so a crash mid-write cannot
    # leave a half-written checkpoint behind.
    def save(path)
      require 'tmpdir'
      dir = ::File.dirname(path)
      ::Dir.mkdir(dir) unless dir.empty? || ::File.directory?(dir)
      tmp = ::File.join(dir, ".#{::File.basename(path)}.#{$$}.#{object_id.abs}.tmp")
      ::File.binwrite(tmp, to_json)
      ::File.rename(tmp, path)
      @path = path
      self
    rescue SystemCallError
      begin; ::File.delete(tmp) if tmp && ::File.exist?(tmp); rescue SystemCallError; end
      raise
    end

    private

      def byte_range(start_index, end_index)
        start_off = offset_of(start_index)
        end_off   = [offset_of(end_index) + block_size, total_size].min
        [start_off, end_off - start_off]
      end

      def ensure_block!(index)
        if index < 0 || index >= block_count
          raise RangeError, "block #{index} is outside 0...#{block_count}"
        end
      end

      def validate!
        required = %w(format_version direction local remote block_size total_size
                      source_digest blocks)
        missing = required.reject { |key| @payload.key?(key) }
        unless missing.empty?
          raise CheckpointCorruptError.new("missing keys: #{missing.join(', ')}", @path)
        end

        if @payload["format_version"] != FORMAT_VERSION
          raise CheckpointCorruptError.new(
            "unsupported format version #{@payload['format_version'].inspect}", @path)
        end

        unless direction == "upload"
          raise CheckpointCorruptError.new("expected direction 'upload', got #{direction.inspect}", @path)
        end

        unless block_size.is_a?(Integer) && block_size > 0
          raise CheckpointCorruptError.new("block_size must be a positive integer", @path)
        end
        unless total_size.is_a?(Integer) && total_size >= 0
          raise CheckpointCorruptError.new("total_size must be a non-negative integer", @path)
        end
        unless source_digest.is_a?(String) && !source_digest.empty?
          raise CheckpointCorruptError.new("source_digest is missing", @path)
        end
        unless @blocks.is_a?(Hash)
          raise CheckpointCorruptError.new("blocks must be an object", @path)
        end
        unless @payload["ranges"].nil? ||
               (@payload["ranges"].is_a?(Array) &&
                @payload["ranges"].all? { |r| r.is_a?(Array) && r.length == 2 &&
                                             r.all? { |v| v.is_a?(Integer) && v >= 0 } })
          raise CheckpointCorruptError.new("ranges must be an array of [offset, length] pairs", @path)
        end

        @blocks.each do |index, digest|
          unless index.is_a?(Integer) && index >= 0 && index < block_count
            raise CheckpointCorruptError.new("block index #{index.inspect} out of range", @path)
          end
          unless digest.is_a?(String) && digest =~ /\A[0-9a-f]{16,}\z/
            raise CheckpointCorruptError.new("block #{index} digest is invalid", @path)
          end
        end

        if @payload["remote_version"] && !@payload["remote_version"].is_a?(Hash)
          raise CheckpointCorruptError.new("remote_version must be an object", @path)
        end
      end
  end

end; end; end
