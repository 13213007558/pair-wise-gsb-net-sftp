require 'common'

# Tests for Net::SFTP::Operations::Copy, the bounded read/write fallback
# used by Net::SFTP::Session#copy_data when the server does not advertise
# the OpenSSH "copy-data" extension. These tests drive the copier against
# an in-memory fake server so that the resulting file contents can be
# compared, byte for byte, with both hand-computed expectations and with
# the server's own "copy-data" extension behavior.
class CopyTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::StatusCodes

  # A minimal in-memory stand-in for the server end of an SFTP session.
  # It answers read/write requests (and the "copy-data" extension) against
  # a single String-backed file, invoking callbacks synchronously.
  class FakeServer
    include Net::SFTP::Constants::StatusCodes

    attr_reader :file, :request_count
    attr_accessor :fail_on_write

    def initialize(file)
      @file = file.dup
      @request_count = 0
      @writes = 0
      @fail_on_write = nil
    end

    # Simulates the OpenSSH "copy-data" extension: the server reads the
    # whole source range before writing it (memmove semantics).
    def copy_data(read_handle, read_offset, write_handle, write_offset, length)
      @request_count += 1
      data = slice(read_offset, length)
      poke(write_offset, data)
      yield response(FX_OK)
    end

    def read(handle, offset, length)
      @request_count += 1
      data = slice(offset, length)
      if data.empty?
        yield response(FX_EOF)
      else
        yield response(FX_OK, :data => data)
      end
    end

    def write(handle, offset, data)
      @request_count += 1
      @writes += 1
      if @fail_on_write == @writes
        yield response(FX_FAILURE)
      else
        poke(offset, data)
        yield response(FX_OK)
      end
    end

    private

      def slice(offset, length)
        return "" if offset >= @file.bytesize
        @file[offset, length] || ""
      end

      def poke(offset, data)
        @file << 0.chr while @file.bytesize < offset
        @file[offset, data.bytesize] = data
      end

      def response(code, extra={})
        Net::SFTP::Response.new(nil, { :code => code }.merge(extra))
      end
  end

  # a hand-computable repeated-byte file: "aaaabbbbccccdddd"
  ORIGINAL = ("a".."d").map { |letter| letter * 4 }.join

  def test_forward_shift_matches_extension_and_hand_computed_result
    # copy bytes [0, 8) ("aaaabbbb") over offset 4: the destination range
    # begins inside the source range, so chunks must be copied backwards
    expected = "aaaa" + "aaaabbbb" + "dddd"

    extension_server = FakeServer.new(ORIGINAL)
    extension_server.copy_data("h", 0, "h", 4, 8) { }
    assert_equal expected, extension_server.file

    fallback_server = FakeServer.new(ORIGINAL)
    copied = copy_via_fallback(fallback_server, 0, 4, 8, :chunk_size => 3)
    assert_equal 8, copied
    assert_equal expected, fallback_server.file
    assert_equal extension_server.file, fallback_server.file
  end

  def test_backward_shift_matches_extension_and_hand_computed_result
    # copy bytes [4, 12) ("bbbbcccc") over offset 0: the destination range
    # precedes the source range, so chunks are copied forwards
    expected = "bbbbcccc" + "ccccdddd"

    extension_server = FakeServer.new(ORIGINAL)
    extension_server.copy_data("h", 4, "h", 0, 8) { }
    assert_equal expected, extension_server.file

    fallback_server = FakeServer.new(ORIGINAL)
    copied = copy_via_fallback(fallback_server, 4, 0, 8, :chunk_size => 3)
    assert_equal 8, copied
    assert_equal expected, fallback_server.file
    assert_equal extension_server.file, fallback_server.file
  end

  def test_non_overlapping_copy_matches_extension
    extension_server = FakeServer.new(ORIGINAL)
    extension_server.copy_data("h", 0, "h", 12, 4) { }

    fallback_server = FakeServer.new(ORIGINAL)
    copied = copy_via_fallback(fallback_server, 0, 12, 4, :chunk_size => 2)

    assert_equal 4, copied
    assert_equal "aaaabbbbccccaaaa", fallback_server.file
    assert_equal extension_server.file, fallback_server.file
  end

  def test_copy_past_end_of_file_reports_actual_bytes_copied
    server = FakeServer.new("aaaabbbb")
    copied = copy_via_fallback(server, 4, 16, 8)

    assert_equal 4, copied
    assert_equal "aaaabbbb" + (0.chr * 8) + "bbbb", server.file
  end

  def test_read_beyond_end_of_file_copies_nothing
    server = FakeServer.new("aaaabbbb")
    copied = copy_via_fallback(server, 16, 0, 8)

    assert_equal 0, copied
    assert_equal "aaaabbbb", server.file
  end

  def test_short_read_stops_copy_and_reports_actual_bytes_copied
    server = FakeServer.new("aaaabbbb")
    copied = copy_via_fallback(server, 6, 0, 8)

    assert_equal 2, copied
    assert_equal "bbaabbbb", server.file
  end

  def test_failed_write_stops_copy_and_reports_bytes_copied_before_it
    server = FakeServer.new(ORIGINAL)
    server.fail_on_write = 2
    response = nil
    copied = copy_via_fallback(server, 0, 16, 8, :chunk_size => 4) { |r| response = r }

    assert_equal 4, copied
    refute response.ok?
    assert_equal ORIGINAL + "aaaa", server.file
  end

  def test_zero_length_copy_issues_no_requests
    server = FakeServer.new(ORIGINAL)
    copied = copy_via_fallback(server, 0, 8, 0)

    assert_equal 0, copied
    assert_equal 0, server.request_count
    assert_equal ORIGINAL, server.file
  end

  private

    def copy_via_fallback(server, read_offset, write_offset, length, options={})
      copied = nil
      Net::SFTP::Operations::Copy.copy(server, "h", read_offset, "h", write_offset, length, options) do |response|
        yield response if block_given?
        copied = response[:copied]
      end
      copied
    end
end
