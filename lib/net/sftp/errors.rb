module Net; module SFTP

  # The base exception class for the SFTP system.
  class Exception < RuntimeError; end

  # The base class for errors raised by the resumable transfer machinery
  # (checkpoint handling and resumed uploads).
  class ResumableError < Net::SFTP::Exception; end

  # Raised when a checkpoint cannot be read or parsed, or when it fails its
  # integrity check. Such a checkpoint must never be trusted to decide which
  # blocks can be skipped; the caller may either abort the transfer or
  # explicitly request a fresh upload with <tt>:restart => true</tt>.
  class CheckpointCorruptError < ResumableError

    # The path of the checkpoint file that could not be loaded, if it came
    # from a file.
    attr_reader :path

    # Create a new corrupt-checkpoint error. +path+ identifies the source of
    # the checkpoint data (and may be nil when the checkpoint was provided
    # in memory), and +reason+ describes why the checkpoint was rejected.
    def initialize(reason, path=nil)
      @path = path
      super("resumable transfer checkpoint is corrupt#{" (#{path})" if path}: #{reason}")
    end
  end

  # Raised when the remote end of a resumed transfer is observed to change
  # while existing blocks are being verified. The upload is aborted before
  # any block is written so that data from different remote versions is
  # never stitched together into the target file.
  class RemoteChangedError < ResumableError

    # The version information recorded at the beginning of the verification
    # phase (a hash with whatever attributes the server reported).
    attr_reader :expected

    # The version information observed when the change was detected.
    attr_reader :observed

    # Create a new remote-changed error. +path+ is the path of the remote
    # file, and +expected+/+observed+ are the version snapshots taken before
    # and during verification.
    def initialize(path, expected, observed)
      @expected = expected
      @observed = observed
      super("remote file #{path.inspect} changed during block verification; "\
            "aborting before writing (expected #{expected.inspect}, observed #{observed.inspect})")
    end
  end

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
end; end
