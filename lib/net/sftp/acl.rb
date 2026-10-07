require 'net/sftp/constants'
require 'net/sftp/protocol/04/attributes'

module Net
  module SFTP

    # A pure-data interpreter for the NFSv4-style access control lists that
    # SFTP protocol version 4 (and later) exposes via
    # Net::SFTP::Protocol::V04::Attributes#acl. It answers two questions
    # without ever opening a connection to a server:
    #
    # * +explain+: given a subject, that subject's groups, the file's owner
    #   and group, and a set of requested permission bits, report for each
    #   bit whether it is allowed, denied, or undecidable -- and which ACE
    #   is responsible for that decision. This is how you answer questions
    #   like "why can this user read the file but not write it?".
    # * +inherit+: given the ACL of a directory, compute the ACL that a
    #   newly created child file or subdirectory should receive.
    #
    # Evaluation follows the ordered allow/deny semantics of NFSv4: ACEs
    # are examined in list order, and the first ACE that both matches the
    # subject and mentions the requested bit decides that bit. ACEs are
    # never reordered (denies are not hoisted ahead of allows), because
    # reordering would change the meaning of the ACL. ACEs of type
    # SYSTEM_AUDIT or SYSTEM_ALARM never grant or deny access, and ACEs
    # flagged INHERIT_ONLY do not apply to the object that carries them.
    #
    # A bit comes back as UNKNOWN when the ACL is missing entirely, when
    # the subject could not be resolved, or when no ACE decides the bit --
    # in those cases the server falls back to policy this library cannot
    # see (mode bits, server-side defaults, and so on). Consequently an
    # ALLOW verdict is a local explanation only: it does not guarantee
    # that a remote open via SFTP will actually succeed.
    module ACL

      # The ACE structure used by the protocol version 4 attributes.
      Entry = Net::SFTP::Protocol::V04::Attributes::ACL

      # The possible verdicts of a Decision.
      ALLOW   = :allow
      DENY    = :deny
      UNKNOWN = :unknown

      # The outcome of evaluating a single permission bit: the bit itself,
      # the verdict (ALLOW, DENY, or UNKNOWN), and the ACE responsible for
      # the verdict (nil when the bit is undecidable).
      Decision = Struct.new(:bit, :verdict, :ace) do
        def allowed?; verdict == ALLOW;   end
        def denied?;  verdict == DENY;    end
        def unknown?; verdict == UNKNOWN; end
      end

      # The special +who+ identifiers defined by NFSv4.
      OWNER    = "OWNER@".freeze
      GROUP    = "GROUP@".freeze
      EVERYONE = "EVERYONE@".freeze

      # All flags that relate to inheritance rather than to access.
      INHERIT_FLAGS = Constants::ACE::Flag::FILE_INHERIT |
                      Constants::ACE::Flag::DIRECTORY_INHERIT |
                      Constants::ACE::Flag::NO_PROPAGATE_INHERIT |
                      Constants::ACE::Flag::INHERIT_ONLY

      class << self

        # Explains, for each bit set in +mask+, whether +principal+ is
        # allowed or denied that access by +acl+, and which ACE made the
        # decision. Returns a hash mapping each requested bit to a
        # Decision.
        #
        # * +acl+: an array of ACE structs (see Entry), or nil if the
        #   server reported no ACL.
        # * +principal+: the name of the user requesting access, matching
        #   the +who+ field of named-user ACEs. If nil (the subject could
        #   not be resolved), every bit is UNKNOWN.
        # * +groups+: the names of the groups the principal belongs to.
        # * +owner+: the name of the user that owns the file (used to
        #   match OWNER@ ACEs).
        # * +group+: the name of the group that owns the file (used to
        #   match GROUP@ ACEs).
        # * +mask+: an integer bitmask of the requested permissions, using
        #   the Net::SFTP::Constants::ACE::Mask constants.
        def explain(acl, principal:, groups: [], owner: nil, group: nil, mask:)
          bits_of(mask).each_with_object({}) do |bit, decisions|
            decisions[bit] = explain_bit(acl, bit, principal, groups, owner, group)
          end
        end

        # Computes the ACL that a newly created child of a directory
        # carrying +acl+ should receive. Pass +directory: true+ when the
        # child is itself a directory.
        #
        # ACEs with FILE_INHERIT propagate to new files, and ACEs with
        # DIRECTORY_INHERIT propagate to new subdirectories. Files cannot
        # carry inheritance flags, so those are stripped from ACEs a file
        # inherits. When NO_PROPAGATE_INHERIT is set, the ACE is inherited
        # by the immediate child as an ordinary effective ACE and reaches
        # no further: it will not appear on grandchildren. INHERIT_ONLY
        # ACEs that keep propagating down a directory tree retain the
        # INHERIT_ONLY flag on subdirectories, so they remain inert on the
        # directories themselves.
        def inherit(acl, directory: false)
          return [] if acl.nil?

          flag = Constants::ACE::Flag
          trigger = directory ? flag::DIRECTORY_INHERIT : flag::FILE_INHERIT

          acl.each_with_object([]) do |ace, inherited|
            next if ace.flag.to_i & trigger == 0

            flags = ace.flag.to_i
            if !directory || flags & flag::NO_PROPAGATE_INHERIT != 0
              flags &= ~INHERIT_FLAGS
            end
            inherited << Entry.new(ace.type, flags, ace.mask, ace.who)
          end
        end

        private

          # Walks the ACL in order and returns the Decision for a single
          # permission bit.
          def explain_bit(acl, bit, principal, groups, owner, group)
            return Decision.new(bit, UNKNOWN, nil) if acl.nil?
            return Decision.new(bit, UNKNOWN, nil) if principal.nil? || principal.to_s.empty?

            acl.each do |ace|
              next unless authorizing?(ace)
              next if ace.flag.to_i & Constants::ACE::Flag::INHERIT_ONLY != 0
              next unless ace.mask.to_i & bit == bit
              next unless matches?(ace, principal, groups, owner, group)

              verdict = ace.type == Constants::ACE::Type::ACCESS_ALLOWED ? ALLOW : DENY
              return Decision.new(bit, verdict, ace)
            end

            Decision.new(bit, UNKNOWN, nil)
          end

          # Only allow/deny ACEs participate in authorization; audit and
          # alarm ACEs merely describe logging behavior.
          def authorizing?(ace)
            ace.type == Constants::ACE::Type::ACCESS_ALLOWED ||
              ace.type == Constants::ACE::Type::ACCESS_DENIED
          end

          # Reports whether the ACE's +who+ identifier selects the given
          # subject.
          def matches?(ace, principal, groups, owner, group)
            case ace.who
            when OWNER
              !owner.nil? && principal == owner
            when GROUP
              !group.nil? && groups.include?(group)
            when EVERYONE
              true
            else
              if ace.flag.to_i & Constants::ACE::Flag::IDENTIFIER_GROUP != 0
                groups.include?(ace.who)
              else
                principal == ace.who
              end
            end
          end

          # Splits an integer mask into its constituent single-bit values.
          def bits_of(mask)
            bits = []
            remaining = mask.to_i
            bit = 1
            while remaining > 0
              bits << bit if remaining & 1 == 1
              remaining >>= 1
              bit <<= 1
            end
            bits
          end

      end

    end

  end
end
