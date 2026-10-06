require "common"

class LockIntegrationTest < Net::SFTP::TestCase
  include Net::SFTP::Constants
  include Net::SFTP::Constants::PacketTypes

  INFINITY = 1.0 / 0

  def test_two_handles_can_interleave_overlapping_lock_requests
    transport = MemoryTransport.new
    sftp = Net::SFTP::Session.new(transport, 6)
    transport.run_until { sftp.open? }

    first_handle = sftp.open!("/locked")
    second_handle = sftp.open!("/locked")
    block_requests = []
    transport.endpoint.on_request(FXP_BLOCK) do |request|
      block_requests << request
    end
    first_lock = sftp.block(first_handle, 10, 20, LockTypes::ALL)
    second_lock = sftp.block(second_handle, 15, 10, LockTypes::WRITE)

    assert first_lock.pending?
    assert second_lock.pending?
    assert_equal [[first_handle, 10, 20, LockTypes::ALL],
                  [second_handle, 15, 10, LockTypes::WRITE]],
                 block_requests.map { |request| request.values_at(:handle, :offset, :length, :mask) }
    sftp.loop { [first_lock, second_lock].any?(&:pending?) }

    assert first_lock.response.ok?
    assert_equal LockTypes::ALL, sftp.locks[first_handle][:acquired].first[:mask]
    assert second_lock.response.lock_conflict?
    assert !second_lock.response.connection_lost?
  end

  def test_zero_length_means_to_eof_and_duplicate_unblock_is_a_protocol_status
    transport = MemoryTransport.new
    sftp = Net::SFTP::Session.new(transport, 6)
    transport.run_until { sftp.open? }

    handle = sftp.open!("/locked")
    sftp.block!(handle, 10, 0, LockTypes::WRITE)
    sftp.unblock!(handle, 10, 0)

    duplicate = sftp.unblock(handle, 10, 0)
    sftp.loop { duplicate.pending? }

    assert duplicate.response.no_matching_byte_range_lock?
    assert_equal 31, duplicate.response.code
  end

  def test_close_gives_a_pending_lock_a_definite_result
    transport = MemoryTransport.new
    sftp = Net::SFTP::Session.new(transport, 6)
    transport.run_until { sftp.open? }

    handle = sftp.open!("/locked")
    lock = nil
    close = nil

    transport.endpoint.hold_next_block!
    lock = sftp.block(handle, 0, 10, LockTypes::WRITE)
    close = sftp.close(handle)

    sftp.loop { lock.pending? || close.pending? }

    assert lock.response.lock_conflict?
    assert close.response.ok?
  end

  def test_transport_interruption_is_distinct_from_lock_conflict
    transport = MemoryTransport.new
    sftp = Net::SFTP::Session.new(transport, 6)
    transport.run_until { sftp.open? }

    handle = sftp.open!("/locked")
    transport.endpoint.hold_next_block!
    lock = sftp.block(handle, 0, 10, LockTypes::WRITE)

    transport.close_channel!
    sftp.loop { lock.pending? }

    assert lock.response.connection_lost?
    assert !lock.response.lock_conflict?
  end

  class MemoryTransport
    attr_reader :channel, :endpoint

    def initialize
      @jobs = []
      @channel = FakeChannel.new(method(:enqueue), method(:endpoint))
      @endpoint = MemoryEndpoint.new(method(:enqueue)) { |frame| enqueue { @channel.receive(frame) } }
      @logger = NullLogger.new
    end

    def logger
      @logger
    end

    def open_channel(&block)
      enqueue { block.call(@channel) }
      @channel
    end

    def loop(&block)
      while block.nil? || block.call
        return unless run_one_job
      end
    end

    def run_until(&block)
      loop { !block.call }
    end

    def close_channel!
      enqueue { @channel.closed! }
    end

    private

      def enqueue(&block)
        @jobs << block
      end

      def run_one_job
        job = @jobs.shift
        return false unless job

        job.call
        true
    end

    class FakeChannel
      def initialize(enqueue, endpoint_provider)
        @endpoint_provider = endpoint_provider
        @enqueue = enqueue
        @input = Net::SSH::Buffer.new
        @data_callbacks = []
        @extended_data_callbacks = []
        @close_callbacks = []
        @process_callbacks = []
      end

      def send_data(data)
        @endpoint_provider.call.receive(data)
      end

      def subsystem(name, &block)
        @enqueue.call { block.call(self, true) }
      end

      def on_data(&block)
        @data_callbacks << block
      end

      def on_extended_data(&block)
        @extended_data_callbacks << block
      end

      def on_close(&block)
        @close_callbacks << block
      end

      def on_process(&block)
        @process_callbacks << block
      end

      def receive(data)
        @enqueue.call do
          @input.append(data)
          process_input while @input.length >= 4 && complete_packet?
          @process_callbacks.each { |callback| callback.call(self) }
        end
      end

      def closed!
        @close_callbacks.each { |callback| callback.call(self) }
      end

      private

        def complete_packet?
          buffer = Net::SSH::Buffer.new(@input.to_s)
          length = buffer.read_long
          @input.length >= length + 4
        end

        def process_input
          buffer = Net::SSH::Buffer.new(@input.to_s)
          length = buffer.read_long
          packet_data = buffer.read(length)
          @input = Net::SSH::Buffer.new(buffer.read(buffer.available))
          packet = Net::SFTP::Packet.new(packet_data)

          framed_data = Net::SSH::Buffer.from(:long, packet_data.length, :raw, packet_data).to_s
          @data_callbacks.each { |callback| callback.call(self, framed_data) }
        end
    end

    class MemoryEndpoint
      include Net::SFTP::Constants
      include Net::SFTP::Constants::PacketTypes
      include Net::SFTP::Constants::StatusCodes

      Lock = Struct.new(:handle, :offset, :length, :mask)

      attr_reader :locks

      def initialize(enqueue, &output)
        @enqueue = enqueue
        @output = output
        @handles = {}
        @next_handle = 0
        @locks = []
        @hold_next_block = false
        @held_blocks = []
        @request_observers = Hash.new { |hash, type| hash[type] = [] }
      end

      def hold_next_block!
        @hold_next_block = true
      end

      def on_request(type, &block)
        @request_observers[type] << block
      end

      def receive(data)
        Net::SSH::Buffer.new(data).read_all do |buffer|
          length = buffer.read_long
          packet = Net::SFTP::Packet.new(buffer.read(length))
          dispatch(packet)
        end
      end

      private

        def dispatch(packet)
          id = packet.read_long

          case packet.type
          when FXP_INIT
            reply(FXP_VERSION, :long, 6)
          when FXP_OPEN
            packet.read_string
            handle = "handle-#{@next_handle}"
            @handles[handle] = true
            @next_handle += 1
            reply(FXP_HANDLE, :long, id, :string, handle)
          when FXP_BLOCK
            handle = packet.read_string
            offset = packet.read_int64
            length = packet.read_int64
            mask = packet.read_long
            observe(FXP_BLOCK, :handle => handle, :offset => offset, :length => length, :mask => mask, :id => id)
            request_block(handle, offset, length, mask, id)
          when FXP_UNBLOCK
            handle = packet.read_string
            offset = packet.read_int64
            length = packet.read_int64
            request_unblock(handle, offset, length, id)
          when FXP_CLOSE
            handle = packet.read_string
            close_handle(handle, id)
          end
        end

        def observe(type, request)
          @request_observers[type].each { |callback| callback.call(request) }
        end

        def request_block(handle, offset, length, mask, id)
          held = @hold_next_block
          @hold_next_block = false

          if held
            @held_blocks << [handle, offset, length, mask, id]
          elsif conflicting_lock?(handle, offset, length, mask)
            status(id, FX_LOCK_CONFLICT, "lock conflict")
          else
            @locks << Lock.new(handle, offset, length, mask)
            status(id, FX_OK)
          end
        end

        def request_unblock(handle, offset, length, id)
          lock = @locks.find do |candidate|
            candidate.handle == handle && candidate.offset == offset && candidate.length == length
          end

          if lock
            @locks.delete(lock)
            status(id, FX_OK)
          else
            status(id, FX_NO_MATCHING_BYTE_RANGE_LOCK, "no matching byte-range lock")
          end
        end

        def close_handle(handle, id)
          held = @held_blocks.select { |candidate| candidate[0] == handle }
          held.each do |candidate|
            @held_blocks.delete(candidate)
            status(candidate[4], FX_LOCK_CONFLICT, "lock canceled by close")
          end

          @locks.delete_if { |lock| lock.handle == handle }
          @handles.delete(handle)
          status(id, FX_OK)
        end

        def conflicting_lock?(handle, offset, length, mask)
          requested_bits = mask & (LockTypes::READ | LockTypes::WRITE | LockTypes::DELETE)
          end_position = length == 0 ? INFINITY : offset + length

          @locks.any? do |lock|
            next false if lock.handle == handle

            existing_bits = lock.mask & (LockTypes::READ | LockTypes::WRITE | LockTypes::DELETE)
            next false if advisory?(lock.mask) && advisory?(mask)
            next false unless ranges_overlap?(offset, end_position, lock)

            conflicting_bits?(existing_bits, requested_bits)
          end
        end

        def conflicting_bits?(existing_bits, requested_bits)
          if existing_bits & LockTypes::READ != 0
            return true if requested_bits & LockTypes::WRITE != 0
          end

          if existing_bits & LockTypes::WRITE != 0
            return true if requested_bits & (LockTypes::READ | LockTypes::WRITE) != 0
          end

          if existing_bits & LockTypes::DELETE != 0
            return true if requested_bits & LockTypes::DELETE != 0
          end

          if requested_bits & LockTypes::READ != 0
            return true if existing_bits & LockTypes::WRITE != 0
          end

          requested_bits & LockTypes::DELETE != 0 && existing_bits & LockTypes::DELETE != 0
        end

        def ranges_overlap?(offset, end_position, lock)
          lock_end = lock.length == 0 ? INFINITY : lock.offset + lock.length
          offset < lock_end && lock.offset < end_position
        end

        def advisory?(mask)
          mask & LockTypes::ADVISORY != 0
        end

        def status(id, code, message=nil, language="en")
          if message
            reply(FXP_STATUS, :long, id, :long, code, :string, message, :string, language)
          else
            reply(FXP_STATUS, :long, id, :long, code)
          end
        end

        def reply(type, *args)
          data = Net::SSH::Buffer.from(*args)
          frame = Net::SSH::Buffer.from(:long, data.length + 1, :byte, type, :raw, data).to_s
          @enqueue.call { @output.call(frame) }
        end
    end

    class NullLogger
      def debug(*); end
      alias_method :info, :debug
      alias_method :warn, :debug
      alias_method :error, :debug
      alias_method :fatal, :debug

      def debug?; false; end
      alias_method :info?, :debug?
      alias_method :warn?, :debug?
      alias_method :error?, :debug?
      alias_method :fatal?, :debug?
    end
  end
end
