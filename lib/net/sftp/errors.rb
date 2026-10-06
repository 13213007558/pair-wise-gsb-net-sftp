module Net; module SFTP

  # The base exception class for the SFTP system.
  class Exception < RuntimeError; end

  # A exception class for reporting a non-success result of an operation.
class StatusException < Net::SFTP::Exception

    # The response object that caused the exception.
    attr_reader :response

    # The error code (numeric)
    attr_reader :code

    # The description of the error
    attr_reader :description

    # Any incident-specific text given when the exception was raised
    attr_reader :text

    # Create a new status exception that reports the given code and
    # description.
    def initialize(response, text=nil)
      @response, @text = response, text
      @code = response.code
      @description = response.message
      @description = Response::MAP[@code] if @description.nil? || @description.empty?
    end

    # Override the default message format, to include the code and
    # description.
    def message
      m = super.dup
      m << " #{text}" if text
      m << " (#{code}, #{description.inspect})"
    end

  end

  # The base class for errors raised by the resumable-transfer machinery.
  class ResumeError < Net::SFTP::Exception; end

  # Raised when a checkpoint file cannot be read or parsed. A corrupt
  # checkpoint must never be trusted, so the transfer is not resumed
  # automatically.
  class CheckpointCorruptError < ResumeError

    # The path of the checkpoint file that could not be loaded.
    attr_reader :path

    # Create a new error for the checkpoint at +path+, wrapping the
    # underlying parsing failure (if any) in +reason+.
    def initialize(message, path=nil, reason=nil)
      @path, @reason = path, reason
      message = "#{message}: #{reason.message}" if reason
      super(message)
    end

    # The underlying exception that caused this error, if any.
    attr_reader :reason
  end

  # Raised when the local source no longer matches the file described by a
  # checkpoint (e.g. its size changed while the connection was down).
  class LocalChangedError < ResumeError

    # The actual size of the local source.
    attr_reader :actual_size

    # The size of the local source recorded in the checkpoint.
    attr_reader :expected_size

    def initialize(message=nil, actual_size=nil, expected_size=nil) #:nodoc:
      @actual_size, @expected_size = actual_size, expected_size
      message ||= "local file changed since the checkpoint was written " \
        "(size #{expected_size.inspect} in checkpoint, #{actual_size.inspect} now)"
      super(message)
    end
  end

  # Raised when the remote end of a transfer changes while its already
  # written blocks are being verified. The transfer is aborted rather than
  # splicing blocks from different remote versions together.
  class RemoteChangedError < ResumeError

    # The remote version info that was recorded before the change was
    # observed.
    attr_reader :expected_version

    # The remote version info observed after the change was detected.
    attr_reader :actual_version

    def initialize(message=nil, expected_version=nil, actual_version=nil) #:nodoc:
      @expected_version, @actual_version = expected_version, actual_version
      message ||= "remote file changed while verifying previously written blocks; " \
        "aborting to avoid mixing remote versions"
      super(message)
    end
  end
end; end
