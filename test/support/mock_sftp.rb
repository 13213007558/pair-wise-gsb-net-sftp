require 'logger'
require 'stringio'
require 'net/sftp/constants'
require 'net/sftp/response'

module Net; module SFTP; module TestSupport

  include Net::SFTP::Constants::StatusCodes

  # An in-memory SFTP server used by the resumable-upload tests.
  #
  # It implements the small slice of the Net::SFTP::Session API that the
  # resumable uploader drives (open/close/read/write/stat/fstat/setstat and
  # an event loop), while recording the exact byte ranges that were READ or
  # confirmed WRITE against each remote file. Every request is asynchronous,
  # just like the real session: the response is delivered only when the event
  # loop is pumped.
  #
  # A new MockSFTPSession starts its request id counter at zero, so creating
  # two sessions in a row reproduces "the original message numbers are reused
  # after reconnect" without any id ever being persisted in the checkpoint.
  # The underlying MockStore can be shared between sessions to emulate
  # reconnecting to the same server.
  class MockSFTPSession
    include Net::SFTP::Constants::OpenFlags
    include Net::SFTP::Constants::StatusCodes

    attr_reader :store, :pending_requests, :logger, :protocol

    def initialize(store = nil)
      @store = store || MockStore.new
      @pending_requests = {}
      @queue = []
      @next_request_id = 0
      @next_handle_id = 0
      @handles = {}
      @write_log = Hash.new { |h, k| h[k] = [] }
      @read_log  = Hash.new { |h, k| h[k] = [] }
      @setstat_log = []
      @write_failures_remaining = nil
      @before_read = nil
      @logger = Logger.new(IO::NULL)
      @protocol = MockProtocol.new(self)
    end

    # Builds a fresh session (request ids restarted at 0) over the same
    # simulated filesystem.
    def self.reconnect(other)
      new(other.store)
    end

    # The value the next allocated request id will have.
    def next_request_id
      @next_request_id
    end

    # Makes the next +count+ WRITE requests succeed, and every WRITE after
    # that fail with FX_CONNECTION_LOST, emulating a connection dying partway
    # through a transfer.
    def fail_writes_after!(count)
      @write_failures_remaining = count
      self
    end

    # Records every SETSTAT as [path, attrs].
    def setstat_log
      @setstat_log
    end

    # Invokes +block+ before every READ is serviced; tests use it to change
    # the remote file while verification is in flight.
    def before_read(&block)
      @before_read = block
      self
    end

    # Test helper: places a file on the simulated server.
    def put_file!(path, data)
      @store.files[path] = MockRemoteFile.new(data)
      self
    end

    def file?(path)
      @store.files.key?(path)
    end

    def data_for(path)
      @store.files[path]&.content
    end

    # Test helper: atomically replaces the remote file's content, the way an
    # out-of-band writer would while the connection was down. The version is
    # bumped so that stat/fstat observers notice.
    def replace_file!(path, data)
      if @store.files[path]
        @store.files[path].replace!(data)
      else
        put_file!(path, data)
      end
      self
    end

    # Byte ranges confirmed WRITTEN on THIS connection only.
    def written_ranges(path)
      @write_log[path]
    end

    # Byte ranges READ on THIS connection only.
    def read_ranges(path)
      @read_log[path]
    end

    def open(path, flags="r", options={}, &callback)
      schedule do
        file = @store.files[path]
        mode = normalize_flags(flags)

        if file.nil?
          if mode[:create]
            file = MockRemoteFile.new("")
            @store.files[path] = file
          else
            next respond_status(callback, FX_NO_SUCH_FILE)
          end
        elsif mode[:trunc]
          file.replace!("")
        end

        handle = "mock-handle-#{@next_handle_id += 1}"
        @handles[handle] = OpenHandle.new(file, path, mode)
        respond_data(callback, :handle => handle)
      end
    end

    def close(handle, &callback)
      schedule do
        entry = @handles.delete(handle)
        respond_status(callback, entry ? FX_OK : FX_FAILURE)
      end
    end

    def read(handle, offset, length, &callback)
      schedule do
        entry = @handles[handle]
        next respond_status(callback, FX_FAILURE) unless entry
        @before_read.call(entry.path, offset, length) if @before_read
        @read_log[entry.path] << [offset, length]
        file = entry.file
        if offset >= file.content.bytesize
          respond_status(callback, FX_EOF)
        else
          chunk = file.content.byteslice(offset, length) || ""
          if chunk.empty?
            respond_status(callback, FX_EOF)
          else
            respond_data(callback, :data => chunk.b)
          end
        end
      end
    end

    def write(handle, offset, data, &callback)
      schedule do
        entry = @handles[handle]
        next respond_status(callback, FX_FAILURE) unless entry
        next respond_status(callback, FX_PERMISSION_DENIED) unless entry.mode[:write]

        if @write_failures_remaining
          if @write_failures_remaining > 0
            @write_failures_remaining -= 1
            entry.file.write!(offset, data.b, @write_log[entry.path])
            respond_status(callback, FX_OK)
          else
            respond_status(callback, FX_CONNECTION_LOST)
          end
        else
          entry.file.write!(offset, data.b, @write_log[entry.path])
          respond_status(callback, FX_OK)
        end
      end
    end

    def stat(path, flags=nil, &callback)
      schedule do
        file = @store.files[path]
        if file
          respond_data(callback, :attrs => file.attrs)
        else
          respond_status(callback, FX_NO_SUCH_FILE)
        end
      end
    end

    def fstat(handle, flags=nil, &callback)
      schedule do
        entry = @handles[handle]
        if entry
          respond_data(callback, :attrs => entry.file.attrs)
        else
          respond_status(callback, FX_FAILURE)
        end
      end
    end

    def setstat(path, attrs, &callback)
      schedule do
        file = @store.files[path]
        if file
          file.setstat!(attrs)
          @setstat_log << [path, Hash[attrs.map { |k, v| [k.to_sym, v] }]]
          respond_status(callback, FX_OK)
        else
          respond_status(callback, FX_NO_SUCH_FILE)
        end
      end
    end

    # Operations entry points, mirroring Net::SFTP::Session.
    def upload_resumable(local, remote = nil, options = {}, &block)
      remote ||= (local.respond_to?(:read) ? "<memory>" : File.basename(local))
      Net::SFTP::Operations::ResumableUpload.new(self, local, remote, options, &block)
    end

    def upload_resumable!(local, remote = nil, options = {}, &block)
      upload_resumable(local, remote, options, &block).wait
    end

    # Delivers the next queued response, invoking its callback synchronously.
    def pump!
      action = @queue.shift
      if action
        action.call
        true
      else
        false
      end
    end

    def loop(&block)
      block ||= Proc.new { @pending_requests.any? }
      while block.call
        break if @queue.empty?
        pump!
      end
      self
    end

    private

      OpenHandle = Struct.new(:file, :path, :mode)

      def normalize_flags(flags)
        if flags.is_a?(String)
          case flags
          when "r"    then { :read => true,  :write => false, :create => false, :trunc => false }
          when "w"    then { :read => false, :write => true,  :create => true,  :trunc => true  }
          when "a"    then { :read => false, :write => true,  :create => true,  :trunc => false }
          when "r+" then { :read => true, :write => true, :create => false, :trunc => false }
          when "a+" then { :read => true, :write => true, :create => true,  :trunc => false }
          else raise ArgumentError, "unsupported mock open flags #{flags.inspect}"
          end
        else
          writable = (flags & (IO::WRONLY | IO::RDWR)) != 0
          readable = (flags & IO::RDWR) != 0
          {
            :read   => readable,
            :write  => writable,
            :create => (flags & IO::CREAT) != 0,
            :trunc  => (flags & IO::TRUNC) != 0
          }
        end
      end

      def schedule(&action)
        id = @next_request_id
        @next_request_id += 1
        request = MockRequest.new(self, id)
        @pending_requests[id] = request
        @queue << Proc.new do
          @pending_requests.delete(id)
          @current_request = request
          action.call
        end
        request
      end

      def respond_status(callback, code)
        request = @current_request
        request.response = Net::SFTP::Response.new(request, :code => code)
        callback.call(request.response) if callback
      end

      def respond_data(callback, data)
        request = @current_request
        request.response = Net::SFTP::Response.new(request, data)
        callback.call(request.response) if callback
      end

    # Minimal stand-in for Net::SFTP::Request.
    class MockRequest
      attr_reader :session, :id
      attr_accessor :response, :properties

      def initialize(session, id)
        @session, @id = session, id
        @properties = {}
      end

      def [](key); @properties[key.to_sym]; end
      def []=(key, value); @properties[key.to_sym] = value; end

      def pending?
        @session.pending_requests.key?(@id)
      end

      def wait
        @session.loop { pending? }
        self
      end
    end

    class MockProtocol
      attr_reader :session
      def initialize(session); @session = session; end
      def version; 3; end
    end

    class MockAttributes
      attr_reader :size, :uid, :gid, :permissions, :atime, :mtime, :extended

      def initialize(file)
        @size        = file.content.bytesize
        @uid         = 1000
        @gid         = 1000
        @permissions = 0o644
        @atime       = file.atime
        @mtime       = file.mtime
        @extended    = { "version" => file.version.to_s }
      end
    end

    # Shared simulated filesystem state (survives across reconnections).
    class MockStore
      attr_reader :files
      def initialize; @files = {}; end
    end

    # A single remote file. Besides its content it remembers the byte ranges
    # of every confirmed write on every connection (the per-connection log is
    # passed in by the session), which is what the acceptance assertions
    # inspect.
    class MockRemoteFile
      attr_reader :content, :version, :mtime, :atime

      def initialize(content)
        @content = content.b
        @version = 1
        @mtime = 1_700_000_000
        @atime = @mtime
      end

      def attrs
        MockAttributes.new(self)
      end

      def write!(offset, data, write_log = nil)
        before = @content.bytesize
        if offset > before
          @content = @content + ("\0" * (offset - before))
        end
        @content.bytesplice(offset, data.bytesize, data)
        write_log << [offset, data.bytesize] if write_log
        touch!
      end

      def replace!(data)
        @content = data.b
        touch!
      end

      def setstat!(attrs)
        attrs.each do |key, value|
          case key.to_sym
          when :size
            size = value.to_i
            if size < @content.bytesize
              @content = @content.byteslice(0, size)
            elsif size > @content.bytesize
              @content = @content + ("\0" * (size - @content.bytesize))
            end
          when :mtime then @mtime = value.to_i
          when :atime then @atime = value.to_i
          end
        end
        touch!
      end

      private

        def touch!
          @version += 1
          @mtime += 1
        end
    end
  end

end; end; end
