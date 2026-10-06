require "common"
require "support/mock_sftp"
require "tmpdir"
require "fileutils"

class ResumableUploadTest < Net::SFTP::TestCase
  BLOCK = 10

  def setup
    prepare_progress!
    @dir = Dir.mktmpdir("resume-upload")
  end

  def teardown
    FileUtils.remove_entry(@dir) if @dir && File.directory?(@dir)
  end

  # Fresh upload: every block is written, checkpoint is removed at the
  # end, and :finish follows the last close acknowledgement.
  def test_fresh_upload_writes_every_block_without_reading
    sftp = mock_sftp
    sftp.put_remote(remote)
    local_file("abcdefghijklmnopqrstuvwxyz")

    upload = run_upload(sftp, :requests => 1)

    assert_equal "abcdefghijklmnopqrstuvwxyz", sftp.remote_file(remote).content
    assert_equal [[0, 10], [10, 20], [20, 26]], all_writes(sftp)
    assert_equal [], sftp.remote_file(remote).read_ranges
    refute File.exist?(ckpt)
    assert_equal [:open, :retransmit, :put, :written, :put, :written,
                  :put, :written, :close, :finish], events
    refute upload.active?
  end

  # Resume with an unchanged remote: recorded blocks are verified with
  # READ and skipped; nothing is re-sent.
  def test_resume_skips_blocks_confirmed_by_read
    sftp = mock_sftp
    sftp.put_remote(remote, "abcdefghijklmnopqrstuvwxyz")
    local_file("abcdefghijklmnopqrstuvwxyz")
    build_checkpoint([0, 10], [10, 10], [20, 6])

    run_upload(sftp)

    assert_equal [], all_writes(sftp)
    reads = sftp.remote_file(remote).read_ranges
    assert_includes reads, [0, 10]
    assert_includes reads, [10, 20]
    assert_includes reads, [20, 26]
    refute File.exist?(ckpt)
  end

  # Equal-length replacement: same size, different bytes in one block.
  # Size alone can't detect it, but the digest comparison does and only
  # the affected range is retransmitted.
  def test_equal_length_replacement_retransmits_only_changed_blocks
    sftp = mock_sftp
    sftp.put_remote(remote, "XXXXXXXXXXklmnopqrstuvwxyz")
    local_file("abcdefghijklmnopqrstuvwxyz")
    build_checkpoint([0, 10], [10, 10], [20, 6])

    run_upload(sftp)

    assert_equal [[0, 10]], all_writes(sftp)
    assert_equal "abcdefghijklmnopqrstuvwxyz", sftp.remote_file(remote).content
    assert_equal [[0, 10]], retransmit_events.last
  end

  # Last block got shorter (remote truncated): the tail block can't be
  # confirmed and is re-sent.
  def test_shorter_last_block_retransmits_tail
    sftp = mock_sftp
    sftp.put_remote(remote, "abcdefghijklmnopqrstuv")
    local_file("abcdefghijklmnopqrstuvwxyz")
    build_checkpoint([0, 10], [10, 10], [20, 6])

    run_upload(sftp)

    assert_equal [[20, 26]], all_writes(sftp)
    assert_equal "abcdefghijklmnopqrstuvwxyz", sftp.remote_file(remote).content
    assert_equal [[20, 26]], retransmit_events.last
  end

  # The opposite case: the remote is longer than the local source.
  # Missing blocks are re-sent and the extra tail is truncated.
  def test_longer_remote_is_truncated_after_writes
    sftp = mock_sftp
    sftp.put_remote(remote, "XXXXXXXXXXklmnopqrstuvwxyz!!!TAIL")
    local_file("abcdefghijklmnopqrstuvwxyz")
    build_checkpoint([0, 10], [10, 10], [20, 6])

    run_upload(sftp)

    assert_equal [[0, 10]], all_writes(sftp)
    assert_equal "abcdefghijklmnopqrstuvwxyz", sftp.remote_file(remote).content
    assert sftp.requests[:fsetstat]
  end

  # Multiple disjoint verified regions: the retransmit event reports
  # exactly the gaps as merged half-open ranges.
  def test_disjoint_completed_intervals_report_gap_ranges
    sftp = mock_sftp
    sftp.put_remote(remote, "abcdefghijXXXXXXXXXXuvwxyz")
    local_file("abcdefghijklmnopqrstuvwxyz")
    build_checkpoint([0, 10], [10, 10], [20, 6])

    run_upload(sftp)

    assert_equal [[10, 20]], all_writes(sftp)
    assert_equal [[10, 20]], retransmit_events.last
  end

  # Damaged checkpoint: resuming must fail loudly, never fall back to a
  # blind offset-based resume.
  def test_corrupt_checkpoint_is_rejected
    sftp = mock_sftp
    local_file("abcdefghij")
    File.write(ckpt, "{not json")

    error = assert_raises(Net::SFTP::CheckpointCorruptError) { run_upload(sftp) }
    assert_equal ckpt, error.path
    assert_equal [], all_writes(sftp)
  end

  # Tampered payload that still parses as JSON: the digest check catches it.
  def test_tampered_checkpoint_payload_is_rejected
    sftp = mock_sftp
    local_file("abcdefghij")
    build_checkpoint([0, 10])
    document = JSON.parse(File.read(ckpt))
    document["payload"]["remote"] = "/elsewhere"
    File.write(ckpt, JSON.dump(document))

    assert_raises(Net::SFTP::CheckpointCorruptError) { run_upload(sftp) }
  end

  # Local source size no longer matches the checkpoint.
  def test_changed_local_file_is_rejected
    sftp = mock_sftp
    sftp.put_remote(remote, "abcdefghij")
    local_file("abcdefghij00")
    build_checkpoint([0, 10], :size => 10)

    error = assert_raises(Net::SFTP::LocalChangedError) { run_upload(sftp) }
    assert_equal 12, error.actual_size
    assert_equal 10, error.expected_size
  end

  # Remote changes *during* verification (identifiers observed via fstat
  # before and after the READs disagree): abort rather than mix versions.
  def test_remote_change_during_verification_aborts
    sftp = mock_sftp
    sftp.put_remote(remote, "abcdefghijklmnopqrstuvwxyz")
    local_file("abcdefghijklmnopqrstuvwxyz")
    build_checkpoint([0, 10], [10, 10], [20, 6])

    # After the first block verifies, an external actor replaces the file
    # with data of a different length.
    reads_seen = 0
    sftp.on_remote_change = nil
    original_read = sftp.method(:read)
    sftp.define_singleton_method(:read) do |handle, offset, length, &cb|
      request = original_read.call(handle, offset, length, &cb)
      reads_seen += 1
      sftp.replace_remote("/remote/file.bin", "zzzzz", 9999) if reads_seen == 1
      request
    end

    assert_raises(Net::SFTP::RemoteChangedError) { run_upload(sftp) }
  end

  # After a reconnect the SFTP message-id space starts again at zero.
  # Resumption must not depend on request ids from the old connection.
  def test_reconnect_reuses_message_ids_and_completes_transfer
    sftp1 = mock_sftp
    sftp1.put_remote(remote)
    local_file("abcdefghijklmnopqrstuvwxyz")

    # First connection: two blocks acknowledged, then the connection dies.
    uploader = sftp1.resume_upload(local, remote,
                                  :checkpoint => ckpt,
                                  :block_size => BLOCK,
                                  :requests => 1)
    sftp1.pump_until { sftp1.request_count >= 6 }
    uploader.abort!

    saved = Net::SFTP::Resume::Checkpoint.load(ckpt)
    assert_equal [[0, 10], [10, 10]],
                 saved.blocks.map { |block| [block['offset'], block['length']] }
    assert_equal [[0, 20]], saved.completed_intervals

    # New connection starts numbering requests from zero again.
    sftp2 = mock_sftp
    sftp2.put_remote(remote, sftp1.remote_file(remote).content,
                     sftp1.remote_file(remote).mtime)
    run_upload(sftp2)

    assert_equal 0, sftp2.first_request_id
    assert_equal "abcdefghijklmnopqrstuvwxyz", sftp2.remote_file(remote).content
    assert_equal [[20, 26]], all_writes(sftp2)
    refute File.exist?(ckpt)
  end

  # Checkpoint records direction: a checkpoint for another direction is
  # rejected.
  def test_checkpoint_wrong_direction_is_rejected
    sftp = mock_sftp
    sftp.put_remote(remote)
    local_file("abcdefghij")
    wrong = Net::SFTP::Resume::Checkpoint.new(
      Net::SFTP::Resume::Checkpoint::DOWNLOAD,
      local, remote, 10, BLOCK)
    wrong.save(ckpt)

    assert_raises(Net::SFTP::ResumeError) { run_upload(sftp) }
  end

  # In-memory sources are supported when no checkpoint path is wanted;
  # the transfer then runs without touching the disk.
  def test_ephemeral_checkpoint_uploads_io_source
    sftp = mock_sftp
    sftp.put_remote(remote)
    io = StringIO.new("abcdefghij")

    uploader = sftp.resume_upload(io, remote,
                                 :checkpoint => nil,
                                 :block_size => BLOCK,
                                 :name => "mem",
                                 :progress => lambda { |*a| record_progress(a) })
    sftp.loop

    refute uploader.active?
    assert_equal "abcdefghij", sftp.remote_file(remote).content
    assert_equal [], Dir.children(@dir)
  end

  # Remote replaced with a file of the exact same size and content that
  # happens to match, but with a changed mtime observed during the
  # post-verification re-stat: still abort rather than risk splicing.
  def test_remote_version_marker_change_aborts_even_with_matching_blocks
    sftp = mock_sftp
    sftp.put_remote(remote, "abcdefghijklmnopqrstuvwxyz")
    local_file("abcdefghijklmnopqrstuvwxyz")
    build_checkpoint([0, 10], [10, 10], [20, 6])

    reads_seen = 0
    original_read = sftp.method(:read)
    sftp.define_singleton_method(:read) do |handle, offset, length, &cb|
      request = original_read.call(handle, offset, length, &cb)
      reads_seen += 1
      # Bump the mtime (same size) after the final READ was queued.
      sftp.remote_file("/remote/file.bin").mtime = 4242 if reads_seen == 3
      request
    end

    assert_raises(Net::SFTP::RemoteChangedError) { run_upload(sftp) }
  end

  private

    def local; File.join(@dir, "local.bin"); end
    def remote; "/remote/file.bin"; end
    def ckpt; File.join(@dir, "local.bin.ckpt"); end
    def pre_crash_ckpt; ckpt; end

    def local_file(data)
      File.binwrite(local, data)
    end

    def mock_sftp
      MockSFTP::Session.new
    end

    def run_upload(sftp, extra_options={})
      options = { :checkpoint => ckpt, :block_size => BLOCK,
                  :requests => 2,
                  :progress => lambda { |*args| record_progress(args) } }
      uploader = sftp.resume_upload(local, remote, options.merge(extra_options))
      sftp.loop
      uploader
    end

    def build_checkpoint(*args)
      options = args.last.is_a?(Hash) ? args.pop : {}
      ranges = args.length == 1 && args.first.is_a?(Array) &&
               (args.first.empty? || args.first.first.is_a?(Array)) ?
               args.first : args
      ranges = [] if ranges.nil?
      size = options[:size] || File.binread(local).bytesize
      data = File.binread(local)
      size ||= data.bytesize
      checkpoint = Net::SFTP::Resume::Checkpoint.new(
        Net::SFTP::Resume::Checkpoint::UPLOAD, local, remote, size, BLOCK)
      ranges.each do |offset, length|
        checkpoint.record_block(offset, length,
          Net::SFTP::Resume::Checkpoint.digest(data.byteslice(offset, length)))
      end
      checkpoint.remote_version = {
        "size" => size, "mtime" => 1000
      }
      checkpoint.save(ckpt)
    end

    def all_writes(sftp)
      file = sftp.remote_file(remote)
      file ? file.written_ranges.sort : []
    end

    def events
      @progress.map(&:first)
    end

    def retransmit_events
      @progress.select { |event| event[0] == :retransmit }
               .map { |event| event[3] }
    end
end
