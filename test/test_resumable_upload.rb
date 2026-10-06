require "common"
require File.expand_path("../support/mock_sftp", __FILE__)
require "digest"
require "fileutils"
require "tmpdir"

class ResumableUploadTest < Minitest::Test
  REMOTE = "/remote/data.bin"
  BLOCK  = Net::SFTP::Operations::ResumableUpload::DEFAULT_BLOCK_SIZE

  def setup
    @tmpdir = Dir.mktmpdir("net-sftp-resumable")
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.directory?(@tmpdir)
  end

  # Fresh upload, no checkpoint: nothing is READ, every block is written in
  # order, and finish comes after close.
  def test_fresh_upload_writes_every_block_without_reads
    data = block_data
    sftp = mock_sftp
    events = []

    sftp.upload_resumable(StringIO.new(data), REMOTE,
                          :block_size => BLOCK,
                          :progress => recorder(events)).wait

    assert_equal data, sftp.data_for(REMOTE)
    assert_equal [], sftp.read_ranges(REMOTE)
    assert_equal [[0, BLOCK], [BLOCK, BLOCK], [2 * BLOCK, 10]],
                 sftp.written_ranges(REMOTE)
    assert_event_order(events)
    assert_equal [[0, 2 * BLOCK + 10]], resume_ranges(events)
  end

  # Disconnect after the first confirmed block. A new connection reuses
  # request ids starting at zero; the surviving block must be READ-verified
  # before it is skipped, and only the hole is re-sent.
  def test_resume_after_disconnect_verifies_then_sends_only_missing_blocks
    data = block_data
    checkpoint = checkpoint_path

    first = mock_sftp
    first.fail_writes_after!(1)
    err = assert_raises(Net::SFTP::StatusException) do
      first.upload_resumable(StringIO.new(data), REMOTE,
                             :block_size => BLOCK,
                             :checkpoint => checkpoint).wait
    end
    assert_equal Net::SFTP::Constants::StatusCodes::FX_CONNECTION_LOST, err.code
    assert File.exist?(checkpoint), "the confirmed block must be checkpointed"
    assert_equal [[0, BLOCK]], first.written_ranges(REMOTE)

    second = Net::SFTP::TestSupport::MockSFTPSession.reconnect(first)
    assert_equal 0, second.next_request_id, "message ids restart on a fresh connection"
    events = []
    second.upload_resumable(StringIO.new(data), REMOTE,
                            :block_size => BLOCK,
                            :checkpoint => checkpoint,
                            :progress => recorder(events)).wait

    assert_equal data, second.data_for(REMOTE)

    # Verification: exactly the one claimed block was read back.
    assert_equal [[0, BLOCK]], second.read_ranges(REMOTE)

    # Only the two missing blocks were re-sent on the new connection.
    assert_equal [[BLOCK, BLOCK], [2 * BLOCK, 10]],
                 second.written_ranges(REMOTE)

    # Reconnect reported the discrete hole that had to be re-transmitted.
    assert_equal [[BLOCK, BLOCK + 10]], resume_ranges(events)
    verify_events = events.select { |e| e[0] == :verify }
    assert_equal [[0, BLOCK, true]], verify_events.map { |e| [e[2], e[3], e[4]] }
    assert_event_order(events)

    # The checkpoint persisted direction, block ranges, per-block content
    # digests and the remote version information observed during transfer.
    cp = Net::SFTP::Operations::ResumableCheckpoint.load_file(checkpoint)
    assert_equal "upload", cp.direction
    assert_equal REMOTE, cp.remote
    assert_equal 3, cp.block_count
    assert_equal [[0, 2 * BLOCK + 10]], cp.recorded_ranges
    expected = Digest::SHA256.hexdigest(data.byteslice(BLOCK, BLOCK))
    assert_equal expected, cp.digest_for(1)
    assert_kind_of Hash, cp.remote_version
    # The snapshot is the version observed when verification began: the
    # partial 1-block upload from the dead connection.
    assert_equal BLOCK, cp.remote_version[:size]
  end

  # Equal-length replacement while the connection was down: sizes match but
  # content differs, so the block must not be skipped and the full file is
  # re-sent.
  def test_equal_length_remote_replacement_forces_resend_of_matching_length_block
    data = block_data
    checkpoint = write_checkpoint_for(data)
    # Only the first block was present before the outage in this scenario:
    # build that checkpoint explicitly, with the server holding an
    # equal-length but different replacement for that block.
    cp = Net::SFTP::Operations::ResumableCheckpoint.load_file(checkpoint)
    (1...cp.block_count).each { |i| cp.unmark(i) }
    cp.refresh_ranges!
    cp.save(checkpoint)

    replaced = "Z" * BLOCK + data.byteslice(BLOCK, BLOCK + 10)

    sftp = mock_sftp
    sftp.put_file!(REMOTE, replaced)
    events = []
    sftp.upload_resumable(StringIO.new(data), REMOTE,
                          :block_size => BLOCK,
                          :checkpoint => checkpoint,
                          :progress => recorder(events)).wait

    assert_equal data, sftp.data_for(REMOTE)
    assert_equal [[0, BLOCK]], sftp.read_ranges(REMOTE)
    # Block 0 could not be trusted (same length, different bytes) and the
    # other blocks were absent, so the complete file was re-sent.
    assert_equal [[0, BLOCK], [BLOCK, BLOCK], [2 * BLOCK, 10]],
                 sftp.written_ranges(REMOTE)
    verify_events = events.select { |e| e[0] == :verify }
    assert_equal [[0, BLOCK, false]], verify_events.map { |e| [e[2], e[3], e[4]] }
    assert_equal [[0, 2 * BLOCK + 10]], resume_ranges(events)
  end

  # The previous upload was longer than the current local content. After
  # verification the file must be truncated to the final size before/while
  # writing the (shorter) last block, leaving no stale tail.
  def test_shorter_last_block_truncates_remote_tail
    shorter = "Q" * 5
    checkpoint = checkpoint_path
    # A checkpoint for the new, shorter content with its first block
    # already verified; the server still holds the previous, longer file.
    cp = Net::SFTP::Operations::ResumableCheckpoint.create(
      :local => "<memory>", :remote => REMOTE,
      :block_size => BLOCK, :total_size => shorter.bytesize,
      :source_digest => Digest::SHA256.hexdigest(shorter))
    cp.mark(0, Digest::SHA256.hexdigest(shorter.byteslice(0, BLOCK)))
    cp.refresh_ranges!
    cp.save(checkpoint)

    stale = shorter.byteslice(0, 5) + "TAIL-DATA-MUST-DIE" * 10
    sftp = mock_sftp
    sftp.put_file!(REMOTE, stale)
    events = []
    sftp.upload_resumable(StringIO.new(shorter), REMOTE,
                          :block_size => BLOCK,
                          :checkpoint => checkpoint,
                          :progress => recorder(events)).wait

    assert_equal shorter, sftp.data_for(REMOTE)
    truncs = sftp.setstat_log.select { |path, attrs| path == REMOTE && attrs[:size] == shorter.bytesize }
    refute_empty truncs, "remote must be resized to the shorter final length"
    assert_event_order(events)
  end

  # A corrupted (tampered/truncated) checkpoint must be rejected rather than
  # treated as "start over" or "trust by length". :restart explicitly starts
  # a fresh transfer.
  def test_corrupt_checkpoint_is_rejected_and_restart_overrides
    data = block_data
    checkpoint = checkpoint_path
    File.binwrite(checkpoint, "{not-json")

    assert_raises(Net::SFTP::CheckpointCorruptError) do
      mock_sftp.upload_resumable(StringIO.new(data), REMOTE,
                                :block_size => BLOCK,
                                :checkpoint => checkpoint).wait
    end

    # Flip one hex digit in a valid checkpoint's mac: the integrity check
    # must catch it.
    good = write_checkpoint_for(data)
    raw = File.read(good)
    tampered = raw.sub(/"mac":"[0-9a-f]+"/) do |m|
      m.sub(/[0-9a-f](?="\z)/) { |d| d == "0" ? "1" : "0" }
    end
    File.binwrite(checkpoint, tampered)
    assert_raises(Net::SFTP::CheckpointCorruptError) do
      mock_sftp.upload_resumable(StringIO.new(data), REMOTE,
                                :block_size => BLOCK,
                                :checkpoint => checkpoint).wait
    end

    File.binwrite(checkpoint, tampered)
    sftp = mock_sftp
    sftp.upload_resumable(StringIO.new(data), REMOTE,
                          :block_size => BLOCK,
                          :checkpoint => checkpoint,
                          :restart => true).wait
    assert_equal data, sftp.data_for(REMOTE)
  end

  # If the remote file changes while blocks are being verified, the upload
  # stops and explains, without issuing a single WRITE.
  def test_remote_change_during_verification_aborts_before_any_write
    data = block_data
    checkpoint = write_checkpoint_for(data)

    original = data.dup
    sftp = mock_sftp
    sftp.put_file!(REMOTE, original)
    sftp.before_read do |path, _offset, _length|
      # Out-of-band replacement after the initial snapshot, before the READ
      # is serviced.
      sftp.replace_file!(path, "N" * data.bytesize)
    end

    error = assert_raises(Net::SFTP::RemoteChangedError) do
      sftp.upload_resumable(StringIO.new(data), REMOTE,
                            :block_size => BLOCK,
                            :checkpoint => checkpoint).wait
    end
    assert_match(/changed during block verification/, error.message)
    assert_equal [], sftp.written_ranges(REMOTE), "no write may happen after a version change"
  end

  # The finish event must not fire until every target block's WRITE has been
  # acknowledged and the CLOSE response is back (no pending requests left).
  def test_finish_event_fires_only_after_all_write_acknowledgements
    data = block_data
    sftp = mock_sftp
    seen_at_finish = nil
    handler = Proc.new do |event, _uploader, *_|
      seen_at_finish = sftp.pending_requests.dup if event == :finish
    end

    sftp.upload_resumable(StringIO.new(data), REMOTE,
                          :block_size => BLOCK,
                          :progress => handler).wait

    refute_nil seen_at_finish
    assert_empty seen_at_finish
    # All target blocks have confirmation-borne write records.
    covered = sftp.written_ranges(REMOTE).sum { |_off, len| len }
    assert_equal data.bytesize, covered
  end

  # Multiple discrete completed intervals survive a checkpoint and yield the
  # remaining ranges in between and after.
  def test_multiple_discrete_intervals_and_pending_ranges
    cp = Net::SFTP::Operations::ResumableCheckpoint.create(
      :local => "<memory>", :remote => REMOTE,
      :block_size => 10, :total_size => 55,
      :source_digest => "deadbeef" * 8)
    digest = Digest::SHA256.hexdigest("x")
    # Confirmed: 0-1, 3; pending: block 2 (middle hole) and the short final
    # block 5, i.e. three discrete completed intervals create two tails.
    # Add block 4 as confirmed too, to keep the last block isolated.
    [0, 1, 3, 4].each { |i| cp.mark(i, digest) }

    assert_equal [[0, 1], [3, 4]], cp.completed_intervals
    assert_equal [[20, 10], [50, 5]], cp.pending_ranges
    assert_equal "upload", cp.direction
    Dir.mktmpdir do |dir|
      path = File.join(dir, "cp.json")
      cp.refresh_ranges!
      cp.save(path)
      loaded = Net::SFTP::Operations::ResumableCheckpoint.load_file(path)
      assert_equal [[0, 20], [30, 20]], loaded.recorded_ranges
      assert_equal [[20, 10], [50, 5]], loaded.pending_ranges
    end
  end

  private

    def mock_sftp
      Net::SFTP::TestSupport::MockSFTPSession.new
    end

    def block_data
      "A" * BLOCK + "B" * BLOCK + "C" * 10
    end

    def checkpoint_path
      File.join(@tmpdir, "transfer.ckpt")
    end

    # Runs one complete successful upload of +data+ to a checkpoint file and
    # returns its path, leaving the remote file behind in the session's
    # (discarded) store.
    def write_checkpoint_for(data)
      path = checkpoint_path
      File.delete(path) if File.exist?(path)
      sftp = mock_sftp
      sftp.upload_resumable(StringIO.new(data), REMOTE,
                            :block_size => BLOCK,
                            :checkpoint => path).wait
      path
    end

    def recorder(events)
      Proc.new { |event, uploader, *args| events << [event, *args] }
    end

    def resume_ranges(events)
      event = events.find { |e| e[0] == :resume }
      refute_nil event, "expected a :resume event"
      event[2]
    end

    def assert_event_order(events)
      names = events.map(&:first)
      assert_includes names, :open
      verify_pos = names.index(:verify)
      resume_pos = names.index(:resume)
      first_put  = names.index(:put)
      close_pos  = names.index(:close)
      finish_pos = names.index(:finish)

      refute_nil resume_pos
      refute_nil finish_pos
      refute_nil close_pos
      if verify_pos
        assert verify_pos > names.index(:open)
        assert verify_pos < resume_pos
      end
      if first_put
        assert first_put >= resume_pos
        assert close_pos > first_put
      end
      # finish must be the very last event and strictly after close.
      assert_equal names.length - 1, finish_pos
      assert finish_pos > close_pos
    end
end
