require "common"

class V6LockTest < Net::SFTP::TestCase
  include Net::SFTP::Constants

  def test_overlapping_locks_for_two_handles_are_dispatched_and_reported_interleaved
    endpoint = MemoryProtocolEndpoint.new
    sftp = connect_sftp(endpoint)

    handle1 = sftp.open!("/file")
    handle2 = sftp.open!("/file")

    results = []
    request1 = sftp.block(handle1, 10, LockRanges::TO_EOF, LockTypes::READ) { |response| results << [:handle1, response] }
    request2 = sftp.block(handle2, 20, 10, LockTypes::READ | LockTypes::WRITE | LockTypes::DELETE) { |response| results << [:handle2, response] }

    process_outbound(sftp, endpoint)
    step_one_reply(sftp, endpoint)
    assert_equal [
      [FXP_BLOCK, handle1, 10, 0, LockTypes::READ],
      [FXP_BLOCK, handle2, 20, 10, LockTypes::READ | LockTypes::WRITE | LockTypes::DELETE]
    ], endpoint.block_requests
    assert_equal 1, results.length
    assert_equal :handle1, results.first.first
    assert results.first.last.ok?
    assert request1.response.ok?
    assert request2.pending?

    step_one_reply(sftp, endpoint)
    assert_equal 2, results.length
    assert_equal :handle2, results.last.first
    assert results.last.last.lock_conflict?
    assert request2.response.lock_conflict?
  ensure
    endpoint&.close
  end

  def test_close_waits_for_pending_unblock_to_receive_definite_result
    endpoint = MemoryProtocolEndpoint.new
    sftp = connect_sftp(endpoint)
    handle = sftp.open!("/file")

    block_request = sftp.block(handle, 0, 5, LockTypes::WRITE)
    pump(sftp, endpoint)
    assert block_request.response.ok?

    unblock_request = sftp.unblock(handle, 0, 5)
    close_request = sftp.close(handle)

    assert_equal [], endpoint.requests_of_type(FXP_CLOSE)
    assert unblock_request.pending?
    assert close_request.pending?

    process_outbound(sftp, endpoint)
    step_one_reply(sftp, endpoint)
    assert unblock_request.response.ok?
    assert_equal [], endpoint.requests_of_type(FXP_CLOSE)
    assert close_request.pending?

    step_one_reply(sftp, endpoint)
    process_outbound(sftp, endpoint)
    assert_equal [[FXP_CLOSE, handle]], endpoint.requests_of_type(FXP_CLOSE)
    step_one_reply(sftp, endpoint)
    assert close_request.response.ok?
    assert_equal({}, sftp.handles[handle][:locks])
  ensure
    endpoint&.close
  end

  def test_zero_length_lock_extends_to_eof_and_repeated_unblock_is_accepted
    endpoint = MemoryProtocolEndpoint.new
    sftp = connect_sftp(endpoint)
    handle = sftp.open!("/file")

    lock_request = sftp.block(handle, 32, LockRanges::TO_EOF, LockTypes::WRITE)
    pump(sftp, endpoint)
    assert lock_request.response.ok?

    unblock_request = sftp.unblock(handle, 32, LockRanges::TO_EOF)
    pump(sftp, endpoint)
    assert unblock_request.response.ok?

    duplicate_unblock = sftp.unblock(handle, 32, LockRanges::TO_EOF)
    pump(sftp, endpoint)
    assert duplicate_unblock.response.ok?

    assert_equal [
      [FXP_UNBLOCK, handle, 32, 0],
      [FXP_UNBLOCK, handle, 32, 0]
    ], endpoint.requests_of_type(FXP_UNBLOCK)
  ensure
    endpoint&.close
  end

  def test_lock_conflict_and_connection_interruption_are_distinct_results
    endpoint = MemoryProtocolEndpoint.new
    sftp = connect_sftp(endpoint)
    handle = sftp.open!("/file")

    acquired = sftp.block(handle, 0, 8, LockTypes::WRITE)
    pump(sftp, endpoint)
    assert acquired.response.ok?

    conflicting = sftp.block(handle, 4, 4, LockTypes::WRITE)
    pump(sftp, endpoint)
    assert conflicting.response.lock_conflict?
    assert_equal Net::SFTP::Constants::StatusCodes::FX_LOCK_CONFLICT, conflicting.response.code

    interrupted = sftp.block(handle, 12, 4, LockTypes::READ)
    endpoint.channel.remote_close!

    assert_equal Net::SFTP::Constants::StatusCodes::FX_CONNECTION_LOST, interrupted.response.code
    refute interrupted.response.lock_conflict?
  ensure
    endpoint&.close
  end

  def test_lock_conflict_raises_a_specific_synchronous_exception
    endpoint = MemoryProtocolEndpoint.new
    sftp = connect_sftp(endpoint)
    handle = sftp.open!("/file")

    sftp.block!(handle, 0, 8, LockTypes::WRITE)

    error = assert_raises(Net::SFTP::LockConflictException) do
      sftp.block!(handle, 4, 4, LockTypes::WRITE)
    end

    assert_kind_of Net::SFTP::StatusException, error
    assert_equal Net::SFTP::Constants::StatusCodes::FX_LOCK_CONFLICT, error.code
  ensure
    endpoint&.close
  end

  def test_connection_interruption_raises_a_specific_synchronous_exception
    endpoint = MemoryProtocolEndpoint.new
    sftp = connect_sftp(endpoint)
    handle = sftp.open!("/file")

    request = sftp.block(handle, 0, 8, LockTypes::READ)
    endpoint.channel.remote_close!

    error = assert_raises(Net::SFTP::ConnectionLostException) { sftp.send(:wait_for, request) }
    assert_kind_of Net::SFTP::StatusException, error
    assert_equal Net::SFTP::Constants::StatusCodes::FX_CONNECTION_LOST, error.code
  ensure
    endpoint&.close
  end

  private

    def connect_sftp(endpoint)
      sftp = Net::SFTP::Session.new(endpoint.ssh, 6)
      endpoint.channel.confirm!
      sftp.connect!
      sftp
    end

    def pump(sftp, endpoint)
      process_all(sftp, endpoint)
    end

    def process_all(sftp, endpoint)
      endpoint.transfer
      process_inbound(sftp, endpoint)
      endpoint.flush_replies
      process_inbound(sftp, endpoint)
    end

    def process_outbound(sftp, endpoint)
      endpoint.transfer
      process_inbound(sftp, endpoint)
    end

    def step_one_reply(sftp, endpoint)
      endpoint.deliver_one_reply
      process_inbound(sftp, endpoint)
    end

    def process_inbound(sftp, endpoint)
      sftp.instance_variable_get(:@channel).instance_variable_get(:@on_process).call(endpoint.channel)
    end

    class MemoryProtocolEndpoint
      include Net::SFTP::Constants::PacketTypes
      include Net::SFTP::Constants::StatusCodes
      include Net::SFTP::Constants::LockTypes
      include Net::SFTP::Constants::LockRanges
      attr_reader :channel, :ssh, :received

      def initialize
        @channel = FakeChannel.new
        @ssh = FakeSSH.new(self)
        @received = []
        @next_handle = 0
        @paths = {}
        @locks = Hash.new { |hash, key| hash[key] = [] }
        @replies = []
      end

      def block_requests
        received.select { |request| request.first == FXP_BLOCK }
      end

      def requests_of_type(type)
        received.select { |request| request.first == type }
      end

      def transfer
        data = channel.consume_outbound
        process(data) unless data.empty?
      end

      def flush_replies
        channel.deliver_inbound(@replies.shift) until @replies.empty?
      end

      def deliver_one_reply
        return if @replies.empty?
        channel.deliver_inbound(@replies.shift)
      end

      def close
        channel.remote_close!
      end

      private

      def process(data)
        buffer = Net::SSH::Buffer.new(data)

        until buffer.eof?
          length = buffer.read_long
          packet = Net::SFTP::Packet.new(buffer.read(length))
          dispatch(packet)
        end
      end

      def dispatch(packet)
        case packet.type
        when FXP_INIT
          reply(FXP_VERSION, :long, 6)
        when FXP_OPEN
          id = packet.read_long
          path = packet.read_string
          packet.read_long
          packet.read_long
          packet.read_long
          handle = "handle-#{@next_handle += 1}"
          @paths[handle] = path
          reply(FXP_HANDLE, :long, id, :string, handle)
        when FXP_BLOCK
          id, handle, offset, length, mask = read_range_request(packet)
          @received << [packet.type, handle, offset, length, mask]
          path = @paths.fetch(handle)

          if conflicting?(path, offset, length, mask)
            status(id, Net::SFTP::Constants::StatusCodes::FX_LOCK_CONFLICT, "lock conflict")
          else
            @locks[path] << [offset, length, mask]
            status(id, Net::SFTP::Constants::StatusCodes::FX_OK)
          end
        when FXP_UNBLOCK
          id, handle, offset, length = read_simple_range_request(packet)
          @received << [packet.type, handle, offset, length]
          path = @paths.fetch(handle)
          @locks[path].delete_if { |lock_offset, lock_length, _| lock_offset == offset && lock_length == length }
          status(id, Net::SFTP::Constants::StatusCodes::FX_OK)
        when FXP_CLOSE
          id = packet.read_long
          handle = packet.read_string
          @received << [packet.type, handle]
          @locks.delete(@paths.delete(handle))
          status(id, Net::SFTP::Constants::StatusCodes::FX_OK)
        end
      end

      def read_range_request(packet)
        [packet.read_long, packet.read_string, packet.read_int64, packet.read_int64, packet.read_long]
      end

      def read_simple_range_request(packet)
        [packet.read_long, packet.read_string, packet.read_int64, packet.read_int64]
      end

      def conflicting?(path, offset, length, mask)
        ending = length.zero? ? Float::INFINITY : offset + length

        @locks[path].any? do |existing_offset, existing_length, existing_mask|
          existing_ending = existing_length.zero? ? Float::INFINITY : existing_offset + existing_length
          offset < existing_ending && existing_offset < ending && (mask & existing_mask) != 0
        end
      end

      def status(id, code, message=nil)
        if message
          reply(FXP_STATUS, :long, id, :long, code, :string, message, :string, "en")
        else
          reply(FXP_STATUS, :long, id, :long, code)
        end
      end

      def reply(type, *args)
        data = Net::SSH::Buffer.from(*args)
        @replies << Net::SSH::Buffer.from(:long, data.length + 1, :byte, type, :raw, data).to_s
      end

    end

    class FakeChannel
      def initialize
        @outbound = "".b
        @confirmation = nil
        @on_close = nil
        @on_process = nil
        @on_data = nil
      end

      def expect_confirmation(&block)
        @confirmation = block
      end

      def send_data(data)
        @outbound << data
      end

      def on_data(&block)
        @on_data = block
      end

      def on_close(&block)
        @on_close = block
      end

      def on_extended_data(*)
      end

      def on_process(&block)
        @on_process = block
      end

      def subsystem(_name, &block)
        @confirmed = block
      end

      def confirm!
        @confirmation.call(self)
        @confirmed.call(self, true)
      end

      def consume_outbound
        data = @outbound
        @outbound = "".b
        data
      end

      def deliver_inbound(data)
        @on_data.call(self, data)
      end

      def process_pending
        @on_process&.call(self)
      end

      def remote_close!
        return if @closed
        @closed = true
        @on_close&.call(self)
      end
    end

    class FakeSSH
      def initialize(endpoint)
        @endpoint = endpoint
      end

      def logger
        nil
      end

      def open_channel(&block)
        @endpoint.channel.expect_confirmation(&block)
        @endpoint.channel
      end

      def loop
        100.times do
          @endpoint.transfer
          @endpoint.flush_replies
          @endpoint.channel.process_pending
          break unless yield
        end
      end
    end
end
