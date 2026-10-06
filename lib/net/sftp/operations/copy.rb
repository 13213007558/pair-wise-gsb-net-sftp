require 'net/sftp/constants'
require 'net/sftp/response'

module Net; module SFTP; module Operations

  # Copies a range of bytes between two open file handles on the server by
  # issuing bounded read and write requests. This is used by
  # Net::SFTP::Session#copy_data as a fallback when the server does not
  # advertise the OpenSSH "copy-data" extension.
  #
  # The client object only needs to quack like Net::SFTP::Session: it must
  # respond to #read(handle, offset, length, &callback) and
  # #write(handle, offset, data, &callback), invoking the callback with a
  # Net::SFTP::Response when the server answers.
  #
  # When the source and destination ranges overlap on the same handle, the
  # copy behaves like memmove: if the destination range begins inside (and
  # after) the source range, chunks are copied from the end of the range
  # backwards, so that no write can clobber source bytes that have not been
  # read yet. Otherwise chunks are copied forwards.
  #
  # The copy stops early if the source hits end-of-file (a short or empty
  # read) or if a write fails. In every case the callback receives a
  # Net::SFTP::Response whose :copied property reports how many bytes were
  # actually copied -- never simply the requested length.
  class Copy
    include Net::SFTP::Constants::StatusCodes

    # The largest number of bytes transferred by a single read or write
    # request while copying.
    DEFAULT_CHUNK_SIZE = 32768

    # Copies +length+ bytes from +read_offset+ within +read_handle+ to
    # +write_offset+ within +write_handle+, using +client+ to issue the
    # read/write requests. When the copy finishes (or stalls), +callback+ is
    # invoked with a Net::SFTP::Response; its :copied property is the number
    # of bytes actually copied. Returns whatever the first read request
    # returned (a Net::SFTP::Request when +client+ is a Net::SFTP::Session),
    # or nil if there was nothing to copy.
    def self.copy(client, read_handle, read_offset, write_handle, write_offset, length, options={}, &callback)
      new(client, options).copy(read_handle, read_offset, write_handle, write_offset, length, &callback)
    end

    def initialize(client, options={}) #:nodoc:
      @client = client
      @chunk_size = options[:chunk_size] || DEFAULT_CHUNK_SIZE
    end

    def copy(read_handle, read_offset, write_handle, write_offset, length, &callback) #:nodoc:
      @callback = callback
      chunks = plan_chunks(read_handle, read_offset, write_handle, write_offset, length)
      copy_chunks(read_handle, read_offset, write_handle, write_offset, chunks, 0)
    end

    private

      # Computes the list of [position, length] chunks that make up the copy,
      # ordered so that overlapping ranges on the same handle are copied in
      # the safe direction (backwards when the destination follows the source,
      # forwards otherwise).
      def plan_chunks(read_handle, read_offset, write_handle, write_offset, length)
        return [] if length <= 0

        backwards = write_handle == read_handle &&
                    write_offset > read_offset &&
                    write_offset < read_offset + length

        chunks = []
        if backwards
          stop = length
          while stop > 0
            start = [stop - @chunk_size, 0].max
            chunks << [start, stop - start]
            stop = start
          end
        else
          start = 0
          while start < length
            chunks << [start, [@chunk_size, length - start].min]
            start += @chunk_size
          end
        end
        chunks
      end

      # Issues the read for the first chunk in +chunks+; the rest of the copy
      # is driven by the read/write callbacks.
      def copy_chunks(read_handle, read_offset, write_handle, write_offset, chunks, copied)
        chunk = chunks.first
        return finish(copied, nil) unless chunk

        position, length = chunk
        @client.read(read_handle, read_offset + position, length) do |read_response|
          if read_response.ok? && !read_response[:data].empty?
            data = read_response[:data]
            @client.write(write_handle, write_offset + position, data) do |write_response|
              if write_response.ok?
                copied += data.bytesize
                if data.bytesize < length
                  # a short read means the source hit end-of-file: stop here
                  finish(copied, write_response)
                else
                  copy_chunks(read_handle, read_offset, write_handle, write_offset, chunks[1..-1], copied)
                end
              else
                # the write failed: report what was copied before it
                finish(copied, write_response)
              end
            end
          else
            # end-of-file, an empty read, or a read error: stop with what we have
            finish(copied, read_response)
          end
        end
      end

      # Invokes the callback with a response whose :copied property reports
      # the number of bytes actually copied.
      def finish(copied, response)
        response ||= Net::SFTP::Response.new(nil, :code => FX_OK)
        response.data[:copied] = copied
        @callback.call(response) if @callback
        nil
      end
  end

end; end; end
