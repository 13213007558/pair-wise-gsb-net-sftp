require "common"
require "tmpdir"
require "fileutils"

class CheckpointTest < Net::SFTP::TestCase
  def setup
    @dir = Dir.mktmpdir("checkpoint")
    @path = File.join(@dir, "x.ckpt")
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def test_records_direction_block_ranges_and_digests
    checkpoint = build(26, 10)
    record(checkpoint, 0)
    record(checkpoint, 10)
    record(checkpoint, 20, 6)

    assert_equal "upload", checkpoint.direction
    assert_equal [[0, 26]], checkpoint.completed_intervals
    assert_equal [], checkpoint.missing_ranges
    assert_equal 3, checkpoint.block_count
  end

  def test_multiple_disjoint_completed_intervals
    checkpoint = build(26, 10)
    record(checkpoint, 0)
    record(checkpoint, 20, 6)

    assert_equal [[0, 10], [20, 26]], checkpoint.completed_intervals
    assert_equal [[10, 20]], checkpoint.missing_ranges
  end

  def test_missing_ranges_merges_adjacent_gaps
    checkpoint = build(30, 10)
    record(checkpoint, 10)

    assert_equal [[0, 10], [20, 30]], checkpoint.missing_ranges
  end

  def test_round_trip_through_json
    checkpoint = build(26, 10)
    record(checkpoint, 0)
    checkpoint.remote_version = { "size" => 26, "mtime" => 1234 }

    restored = Net::SFTP::Resume::Checkpoint.parse(checkpoint.to_json)

    assert_equal checkpoint.direction, restored.direction
    assert_equal checkpoint.local, restored.local
    assert_equal checkpoint.remote, restored.remote
    assert_equal 26, restored.local_size
    assert_equal 10, restored.block_size
    assert_equal checkpoint.completed_intervals, restored.completed_intervals
    assert_equal checkpoint.blocks.first["digest"], restored.blocks.first["digest"]
    assert_equal({ "size" => 26, "mtime" => 1234 }, restored.remote_version)
  end

  def test_save_and_load_round_trip
    checkpoint = build(26, 10)
    record(checkpoint, 0)
    checkpoint.save(@path)

    restored = Net::SFTP::Resume::Checkpoint.load(@path)
    assert_equal [[0, 10]], restored.completed_intervals
    assert_equal [[10, 26]], restored.missing_ranges
  end

  def test_truncated_file_is_corrupt
    checkpoint = build(26, 10)
    checkpoint.save(@path)
    File.write(@path, File.read(@path)[0, 20])

    error = assert_raises(Net::SFTP::CheckpointCorruptError) do
      Net::SFTP::Resume::Checkpoint.load(@path)
    end
    assert_equal @path, error.path
  end

  def test_tampered_payload_is_corrupt
    checkpoint = build(26, 10)
    checkpoint.save(@path)
    doc = JSON.parse(File.read(@path))
    doc["payload"]["local_size"] = 99
    File.write(@path, JSON.dump(doc))

    assert_raises(Net::SFTP::CheckpointCorruptError) do
      Net::SFTP::Resume::Checkpoint.load(@path)
    end
  end

  def test_garbage_is_corrupt
    File.write(@path, "nonsense")
    assert_raises(Net::SFTP::CheckpointCorruptError) do
      Net::SFTP::Resume::Checkpoint.load(@path)
    end
  end

  def test_invalid_direction_is_rejected
    assert_raises(ArgumentError) do
      Net::SFTP::Resume::Checkpoint.new(:sideways, "l", "r", 1, 1)
    end
  end

  def test_last_block_is_shorter_than_block_size
    checkpoint = build(23, 10)
    0.step(22, 10) do |offset|
      record(checkpoint, offset, [10, 23 - offset].min)
    end

    assert_equal [[0, 23]], checkpoint.completed_intervals
  end

  private

    def build(size, block_size)
      Net::SFTP::Resume::Checkpoint.new(
        Net::SFTP::Resume::Checkpoint::UPLOAD, "local", "remote",
        size, block_size)
    end

    def record(checkpoint, offset, length=10)
      data = ("a".b * offset) + (offset.chr.b * length)
      checkpoint.record_block(offset, length,
        Net::SFTP::Resume::Checkpoint.digest(data))
    end
end
