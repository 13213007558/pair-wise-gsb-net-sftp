require 'net/sftp/resume/checkpoint'

module Net; module SFTP; module Resume

  # Verifies blocks that are already present at the destination of a
  # resumable transfer before they are skipped.
  #
  # The default implementation uses only ordinary SFTP READ requests:
  # it opens nothing itself and never executes remote shell commands. This
  # keeps verification working against servers that implement the base
  # SFTP protocol but no checksum, hash, or copy-extension. A server that
  # does support a checksum extension could be handled by passing a
  # custom verifier object (responding to #verify) to the transfer.
  class BlockVerifier

    # The maximum number of bytes to request in a single SFTP READ while
    # verifying a block.
    attr_reader :read_size

    # Creates a new verifier. +read_size+ bounds each individual READ
    # request; servers are allowed to return fewer bytes than requested,
    # so reads continue until a full block is assembled or EOF/error is
    # reached.
    def initialize(read_size=nil)
      @read_size = read_size
    end

    # Reads the block identified by +block+ (a hash with 'offset',
    # 'length', and 'digest') from the open remote +handle+, using
    # +sftp+ for the READ requests. When the whole block has been read
    # the block is yielded to +continuation+ as
    # <tt>[ok, actual_data]</tt>, where +ok+ is true only when exactly
    # +length+ bytes were read and their digest matches.
    #
    # The method is asynchronous and requires the SFTP event loop to be
    # run in order to progress.
    def verify(sftp, handle, block, read_size=nil, &continuation)
      size = read_size || @read_size || block['length']
      buffer = ''.b
      Reader.new(sftp, handle, block, Integer(size), buffer, continuation).run
    end

    # Encapsulates the state of a single in-progress block verification.
    class Reader #:nodoc:

      def initialize(sftp, handle, block, read_size, buffer, continuation)
        @sftp = sftp
        @handle = handle
        @block = block
        @read_size = read_size
        @buffer = buffer
        @continuation = continuation
      end

      def run
        request_next
      end

      private

      def request_next
        remaining = @block['length'] - @buffer.bytesize
        length = remaining < @read_size ? remaining : @read_size
        offset = @block['offset'] + @buffer.bytesize
        request = @sftp.read(@handle, offset, length, &method(:on_read))
        request[:resume_verification] = self
      end

      def on_read(response)
        if response.eof?
          finish(false)
        elsif !response.ok?
          raise StatusException.new(response, "read while verifying block at #{@block['offset']}")
        else
          @buffer << response[:data].to_s
          if @buffer.bytesize >= @block['length']
            actual = @buffer.byteslice(0, @block['length'])
            digest = Checkpoint.digest(actual)
            finish(digest == @block['digest'].downcase, actual)
          else
            request_next
          end
        end
      end

      def finish(ok, data=@buffer)
        @continuation.call(ok, data)
      end
    end
  end

end; end; end
