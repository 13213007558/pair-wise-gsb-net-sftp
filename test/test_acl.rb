require 'common'

class TestACL < Net::SFTP::TestCase

  Entry = Net::SFTP::ACL::Entry
  Type  = Net::SFTP::Constants::ACE::Type
  Flag  = Net::SFTP::Constants::ACE::Flag
  Mask  = Net::SFTP::Constants::ACE::Mask

  def test_explain_reports_per_bit_verdict_and_responsible_ace
    acl = [
      allow(Mask::READ_DATA, "OWNER@"),
      deny(Mask::WRITE_DATA, "OWNER@")
    ]

    result = Net::SFTP::ACL.explain(acl,
      :principal => "jamis", :owner => "jamis",
      :mask => Mask::READ_DATA | Mask::WRITE_DATA)

    assert result[Mask::READ_DATA].allowed?
    assert_equal acl[0], result[Mask::READ_DATA].ace
    assert result[Mask::WRITE_DATA].denied?
    assert_equal acl[1], result[Mask::WRITE_DATA].ace
  end

  def test_swapping_two_aces_can_change_the_verdict
    allow_read = allow(Mask::READ_DATA, "EVERYONE@")
    deny_read  = deny(Mask::READ_DATA, "EVERYONE@")

    forward = Net::SFTP::ACL.explain([allow_read, deny_read],
      :principal => "jamis", :mask => Mask::READ_DATA)
    swapped = Net::SFTP::ACL.explain([deny_read, allow_read],
      :principal => "jamis", :mask => Mask::READ_DATA)

    assert forward[Mask::READ_DATA].allowed?
    assert_equal allow_read, forward[Mask::READ_DATA].ace
    assert swapped[Mask::READ_DATA].denied?
    assert_equal deny_read, swapped[Mask::READ_DATA].ace
  end

  def test_named_user_and_named_group_aces
    acl = [
      deny(Mask::READ_DATA, "mallory"),
      allow(Mask::READ_DATA, "devs", Flag::IDENTIFIER_GROUP)
    ]

    mallory = Net::SFTP::ACL.explain(acl,
      :principal => "mallory", :groups => %w[devs], :mask => Mask::READ_DATA)
    jamis = Net::SFTP::ACL.explain(acl,
      :principal => "jamis", :groups => %w[devs], :mask => Mask::READ_DATA)
    outsider = Net::SFTP::ACL.explain(acl,
      :principal => "nobody", :groups => %w[ops], :mask => Mask::READ_DATA)

    assert mallory[Mask::READ_DATA].denied?
    assert jamis[Mask::READ_DATA].allowed?
    assert_equal acl[1], jamis[Mask::READ_DATA].ace
    assert outsider[Mask::READ_DATA].unknown?
  end

  def test_owner_at_matches_file_owner
    acl = [allow(Mask::WRITE_DATA, "OWNER@")]

    owner = Net::SFTP::ACL.explain(acl,
      :principal => "jamis", :owner => "jamis", :mask => Mask::WRITE_DATA)
    other = Net::SFTP::ACL.explain(acl,
      :principal => "mallory", :owner => "jamis", :mask => Mask::WRITE_DATA)

    assert owner[Mask::WRITE_DATA].allowed?
    assert other[Mask::WRITE_DATA].unknown?
  end

  def test_group_at_matches_file_owning_group
    acl = [allow(Mask::READ_DATA, "GROUP@")]

    member = Net::SFTP::ACL.explain(acl,
      :principal => "jamis", :groups => %w[devs], :group => "devs",
      :mask => Mask::READ_DATA)
    stranger = Net::SFTP::ACL.explain(acl,
      :principal => "jamis", :groups => %w[devs], :group => "ops",
      :mask => Mask::READ_DATA)

    assert member[Mask::READ_DATA].allowed?
    assert stranger[Mask::READ_DATA].unknown?
  end

  def test_inherit_only_aces_do_not_apply_to_the_current_object
    acl = [allow(Mask::READ_DATA, "EVERYONE@", Flag::INHERIT_ONLY)]

    result = Net::SFTP::ACL.explain(acl,
      :principal => "jamis", :mask => Mask::READ_DATA)

    assert result[Mask::READ_DATA].unknown?
    assert_nil result[Mask::READ_DATA].ace
  end

  def test_audit_and_alarm_aces_never_authorize
    acl = [
      ace(Type::SYSTEM_AUDIT, 0, Mask::READ_DATA, "EVERYONE@"),
      ace(Type::SYSTEM_ALARM, 0, Mask::READ_DATA, "EVERYONE@")
    ]

    result = Net::SFTP::ACL.explain(acl,
      :principal => "jamis", :mask => Mask::READ_DATA)

    assert result[Mask::READ_DATA].unknown?
    assert_nil result[Mask::READ_DATA].ace
  end

  def test_missing_acl_is_undecidable
    result = Net::SFTP::ACL.explain(nil,
      :principal => "jamis", :mask => Mask::READ_DATA | Mask::WRITE_DATA)

    assert result[Mask::READ_DATA].unknown?
    assert result[Mask::WRITE_DATA].unknown?
  end

  def test_unresolvable_principal_is_undecidable
    acl = [allow(Mask::READ_DATA, "EVERYONE@")]

    result = Net::SFTP::ACL.explain(acl,
      :principal => nil, :mask => Mask::READ_DATA)

    assert result[Mask::READ_DATA].unknown?
  end

  def test_bit_not_mentioned_by_any_ace_is_unknown_not_denied
    acl = [allow(Mask::READ_DATA, "EVERYONE@")]

    result = Net::SFTP::ACL.explain(acl,
      :principal => "jamis", :mask => Mask::READ_DATA | Mask::WRITE_DATA)

    assert result[Mask::READ_DATA].allowed?
    assert result[Mask::WRITE_DATA].unknown?
  end

  def test_inherit_selects_aces_by_child_type
    parent = [
      allow(Mask::READ_DATA, "EVERYONE@", Flag::FILE_INHERIT),
      deny(Mask::WRITE_DATA, "EVERYONE@", Flag::DIRECTORY_INHERIT),
      allow(Mask::EXECUTE, "EVERYONE@")
    ]

    file_acl = Net::SFTP::ACL.inherit(parent, :directory => false)
    dir_acl  = Net::SFTP::ACL.inherit(parent, :directory => true)

    assert_equal 1, file_acl.length
    assert_equal Mask::READ_DATA, file_acl.first.mask
    assert_equal 0, file_acl.first.flag & Net::SFTP::ACL::INHERIT_FLAGS

    assert_equal 1, dir_acl.length
    assert_equal Mask::WRITE_DATA, dir_acl.first.mask
    assert_equal Flag::DIRECTORY_INHERIT,
      dir_acl.first.flag & Flag::DIRECTORY_INHERIT
  end

  def test_no_propagate_inherit_reaches_children_but_not_grandchildren
    flags = Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT |
            Flag::NO_PROPAGATE_INHERIT
    parent = [allow(Mask::READ_DATA, "EVERYONE@", flags)]

    child = Net::SFTP::ACL.inherit(parent, :directory => true)
    assert_equal 1, child.length
    assert_equal 0, child.first.flag & Net::SFTP::ACL::INHERIT_FLAGS

    # the inherited ACE is effective on the child itself
    result = Net::SFTP::ACL.explain(child,
      :principal => "jamis", :mask => Mask::READ_DATA)
    assert result[Mask::READ_DATA].allowed?

    # but it propagates no further
    grandchild = Net::SFTP::ACL.inherit(child, :directory => true)
    assert_equal [], grandchild
  end

  def test_inherit_only_stays_inert_on_subdirectories_and_applies_to_files
    flags = Flag::INHERIT_ONLY | Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT
    parent = [allow(Mask::READ_DATA, "EVERYONE@", flags)]

    child_dir = Net::SFTP::ACL.inherit(parent, :directory => true)
    assert_equal 1, child_dir.length
    assert_equal flags, child_dir.first.flag

    # still inherit-only on the subdirectory, so it decides nothing there
    on_dir = Net::SFTP::ACL.explain(child_dir,
      :principal => "jamis", :mask => Mask::READ_DATA)
    assert on_dir[Mask::READ_DATA].unknown?

    # a file created inside that subdirectory gets an effective ACE
    grandchild_file = Net::SFTP::ACL.inherit(child_dir, :directory => false)
    assert_equal 1, grandchild_file.length
    assert_equal 0, grandchild_file.first.flag & Net::SFTP::ACL::INHERIT_FLAGS

    on_file = Net::SFTP::ACL.explain(grandchild_file,
      :principal => "jamis", :mask => Mask::READ_DATA)
    assert on_file[Mask::READ_DATA].allowed?
  end

  private

    def ace(type, flag, mask, who)
      Entry.new(type, flag, mask, who)
    end

    def allow(mask, who, flag=0)
      ace(Type::ACCESS_ALLOWED, flag, mask, who)
    end

    def deny(mask, who, flag=0)
      ace(Type::ACCESS_DENIED, flag, mask, who)
    end

end
