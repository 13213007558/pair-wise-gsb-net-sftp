require 'common'

class TestACLInterpreter < Net::SFTP::TestCase
  ACE = Net::SFTP::Protocol::V04::Attributes::ACL
  Type = Net::SFTP::Constants::ACE::Type
  Flag = Net::SFTP::Constants::ACE::Flag
  Mask = Net::SFTP::Constants::ACE::Mask

  Interpreter = Net::SFTP::ACLInterpreter

  def ace(type, flag, mask, who)
    ACE.new(type, flag, mask, who)
  end

  def allow(mask, who, flag=0)
    ace(Type::ACCESS_ALLOWED, flag, mask, who)
  end

  def deny(mask, who, flag=0)
    ace(Type::ACCESS_DENIED, flag, mask, who)
  end

  def evaluate(acl, mask, **opts)
    Interpreter.evaluate(**{
      :acl => acl, :user => "alice", :groups => %w(dev staff),
      :owner => "bob", :group => "dev", :mask => mask
    }.merge(opts))
  end

  def test_evaluate_reports_per_bit_verdict_and_deciding_ace
    allow_read = allow(Mask::READ_DATA, "alice")
    deny_write = deny(Mask::WRITE_DATA, "alice")
    acl = [allow_read, deny_write]

    result = evaluate(acl, Mask::READ_DATA | Mask::WRITE_DATA)

    assert result[Mask::READ_DATA].allowed?
    assert_same allow_read, result[Mask::READ_DATA].ace
    assert result[Mask::WRITE_DATA].denied?
    assert_same deny_write, result[Mask::WRITE_DATA].ace
    refute result.permitted?
    assert result.denied?
    refute result.unknown?
  end

  def test_evaluate_is_ordered_so_swapping_entries_changes_the_verdict
    allow_read = allow(Mask::READ_DATA, "alice")
    deny_read = deny(Mask::READ_DATA, "alice")

    allow_first = evaluate([allow_read, deny_read], Mask::READ_DATA)
    deny_first = evaluate([deny_read, allow_read], Mask::READ_DATA)

    assert allow_first[Mask::READ_DATA].allowed?
    assert_same allow_read, allow_first[Mask::READ_DATA].ace
    assert deny_first[Mask::READ_DATA].denied?
    assert_same deny_read, deny_first[Mask::READ_DATA].ace
  end

  def test_evaluate_does_not_let_later_entries_override_an_decided_bit
    acl = [allow(Mask::READ_DATA, "alice"), deny(Mask::READ_DATA, "EVERYONE@")]

    result = evaluate(acl, Mask::READ_DATA)

    assert result[Mask::READ_DATA].allowed?
  end

  def test_inherit_only_entries_do_not_apply_to_the_current_object
    acl = [allow(Mask::READ_DATA, "alice", Flag::INHERIT_ONLY)]

    result = evaluate(acl, Mask::READ_DATA)

    assert result[Mask::READ_DATA].unknown?
    assert_nil result[Mask::READ_DATA].ace
  end

  def test_audit_and_alarm_entries_never_authorize
    audit = ace(Type::SYSTEM_AUDIT, 0, Mask::READ_DATA, "alice")
    alarm = ace(Type::SYSTEM_ALARM, 0, Mask::READ_DATA, "alice")
    deny_read = deny(Mask::READ_DATA, "alice")

    result = evaluate([audit, alarm], Mask::READ_DATA)
    assert result[Mask::READ_DATA].unknown?

    result = evaluate([audit, deny_read], Mask::READ_DATA)
    assert result[Mask::READ_DATA].denied?
    assert_same deny_read, result[Mask::READ_DATA].ace
  end

  def test_owner_group_everyone_and_named_principals
    assert evaluate([allow(Mask::READ_DATA, "OWNER@")], Mask::READ_DATA,
      :user => "bob")[Mask::READ_DATA].allowed?

    assert evaluate([allow(Mask::READ_DATA, "GROUP@")], Mask::READ_DATA)[Mask::READ_DATA].allowed?

    assert evaluate([allow(Mask::READ_DATA, "GROUP@")], Mask::READ_DATA,
      :groups => %w(staff))[Mask::READ_DATA].unknown?

    named_group = allow(Mask::READ_DATA, "dev", Flag::IDENTIFIER_GROUP)
    assert evaluate([named_group], Mask::READ_DATA)[Mask::READ_DATA].allowed?

    named_user_as_group = allow(Mask::READ_DATA, "alice", Flag::IDENTIFIER_GROUP)
    assert evaluate([named_user_as_group], Mask::READ_DATA)[Mask::READ_DATA].unknown?

    assert evaluate([allow(Mask::READ_DATA, "EVERYONE@")], Mask::READ_DATA,
      :user => "mallory", :groups => [])[Mask::READ_DATA].allowed?
  end

  def test_group_at_is_not_matched_when_owning_group_is_unknown
    result = evaluate([allow(Mask::READ_DATA, "GROUP@")], Mask::READ_DATA, :group => nil)

    assert result[Mask::READ_DATA].unknown?
  end

  def test_unknown_when_acl_or_principal_cannot_be_resolved
    assert evaluate(nil, Mask::READ_DATA)[Mask::READ_DATA].unknown?
    assert evaluate([], Mask::READ_DATA)[Mask::READ_DATA].unknown?
    assert evaluate([allow(Mask::READ_DATA, "alice")], Mask::READ_DATA,
      :user => nil)[Mask::READ_DATA].unknown?
    assert evaluate([allow(Mask::READ_DATA, "alice")], Mask::READ_DATA,
      :groups => nil)[Mask::READ_DATA].unknown?
  end

  def test_unknown_for_bits_no_applicable_entry_mentions
    result = evaluate([allow(Mask::READ_DATA, "alice")],
      Mask::READ_DATA | Mask::WRITE_DATA)

    assert result[Mask::READ_DATA].allowed?
    assert result[Mask::WRITE_DATA].unknown?
    assert result.unknown?
    refute result.permitted?
  end

  def test_permitted_when_every_bit_is_allowed
    acl = [allow(Mask::READ_DATA | Mask::WRITE_DATA, "alice")]

    result = evaluate(acl, Mask::READ_DATA | Mask::WRITE_DATA)

    assert result.permitted?
    refute result.denied?
    refute result.unknown?
  end

  def test_inherit_file_child_keeps_only_file_inherit_entries
    file_rule = allow(Mask::READ_DATA, "alice",
      Flag::FILE_INHERIT | Flag::INHERIT_ONLY)
    dir_rule = allow(Mask::WRITE_DATA, "alice",
      Flag::DIRECTORY_INHERIT | Flag::INHERIT_ONLY)
    plain = allow(Mask::EXECUTE, "alice")

    inherited = Interpreter.inherit([file_rule, dir_rule, plain], :directory => false)

    assert_equal 1, inherited.length
    entry = inherited.first
    assert_equal Mask::READ_DATA, entry.mask
    assert_equal "alice", entry.who
    assert_equal 0, entry.flag & (Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT |
      Flag::NO_PROPAGATE_INHERIT | Flag::INHERIT_ONLY)
  end

  def test_inherit_directory_child_keeps_only_directory_inherit_entries
    dir_rule = allow(Mask::READ_DATA, "alice",
      Flag::DIRECTORY_INHERIT | Flag::INHERIT_ONLY)
    file_rule = allow(Mask::WRITE_DATA, "alice", Flag::FILE_INHERIT)

    inherited = Interpreter.inherit([dir_rule, file_rule], :directory => true)

    assert_equal 1, inherited.length
    entry = inherited.first
    assert_equal Mask::READ_DATA, entry.mask
    assert_equal 0, entry.flag & Flag::INHERIT_ONLY
    assert_equal Flag::DIRECTORY_INHERIT, entry.flag & Flag::DIRECTORY_INHERIT
  end

  def test_no_propagate_entries_reach_the_child_but_not_the_grandchild
    no_propagate = allow(Mask::READ_DATA, "alice",
      Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT |
        Flag::NO_PROPAGATE_INHERIT | Flag::INHERIT_ONLY)
    propagating = allow(Mask::WRITE_DATA, "alice",
      Flag::DIRECTORY_INHERIT | Flag::INHERIT_ONLY)

    child = Interpreter.inherit([no_propagate, propagating], :directory => true)
    assert_equal 2, child.length

    stopped = child.find { |entry| entry.mask == Mask::READ_DATA }
    assert_equal 0, stopped.flag & (Flag::FILE_INHERIT |
      Flag::DIRECTORY_INHERIT | Flag::NO_PROPAGATE_INHERIT |
      Flag::INHERIT_ONLY)

    grandchild = Interpreter.inherit(child, :directory => true)
    assert_equal [Mask::WRITE_DATA], grandchild.map(&:mask)
  end

  def test_inherit_returns_nil_for_missing_acl_and_does_not_mutate_input
    assert_nil Interpreter.inherit(nil, :directory => true)

    original = allow(Mask::READ_DATA, "alice",
      Flag::FILE_INHERIT | Flag::INHERIT_ONLY)
    Interpreter.inherit([original], :directory => false)
    assert_equal Flag::FILE_INHERIT | Flag::INHERIT_ONLY, original.flag
  end
end
