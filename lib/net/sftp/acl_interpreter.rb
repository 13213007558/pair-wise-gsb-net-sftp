require 'net/sftp/constants'

module Net
  module SFTP

    # A pure-data interpreter for the NFSv4-style access control lists that
    # SFTP protocol version 4 (and later) exposes via
    # Net::SFTP::Protocol::V04::Attributes#acl.
    #
    # It answers two questions without ever talking to a server:
    #
    # * "May this subject perform these operations on this object?"
    #   (ACLInterpreter.evaluate)
    # * "Which entries of this directory's ACL propagate to a newly created
    #   child file or subdirectory?" (ACLInterpreter.inherit)
    #
    # The evaluation follows the ordered allow/deny semantics of NFSv4: the
    # ACL is scanned from first entry to last, and the first entry that both
    # matches the subject and mentions a given permission bit decides that
    # bit. Entries are never reordered (in particular, denies are NOT given
    # priority over allows), and SYSTEM_AUDIT / SYSTEM_ALARM entries are
    # ignored because they describe logging, not authorization.
    #
    # The result is a best-effort local prediction only. A server may apply
    # additional policy (or be unable to resolve a principal), so an +:allow+
    # verdict does not guarantee that a remote open will succeed; whenever
    # the interpreter lacks the information to decide a bit it reports
    # +:unknown+ instead of guessing.
    module ACLInterpreter
      extend self

      Type  = Constants::ACE::Type
      Flag  = Constants::ACE::Flag
      Mask  = Constants::ACE::Mask

      # The pseudo-identifiers defined by the protocol. Any other +who+
      # string names a concrete user, or a concrete group when the entry's
      # IDENTIFIER_GROUP flag is set.
      OWNER    = "OWNER@"
      GROUP    = "GROUP@"
      EVERYONE = "EVERYONE@"

      # The outcome of evaluating a single permission bit. +verdict+ is one
      # of +:allow+, +:deny+ or +:unknown+, and +ace+ is the ACL entry that
      # produced the verdict (+nil+ when the bit could not be decided).
      Decision = Struct.new(:mask, :verdict, :ace) do
        def allowed?
          verdict == :allow
        end

        def denied?
          verdict == :deny
        end

        def unknown?
          verdict == :unknown
        end
      end

      # The per-bit outcome of ACLInterpreter.evaluate. Each requested
      # permission bit maps to a Decision describing whether it is allowed,
      # denied, or undecidable, and which ACL entry was responsible.
      class Result
        include Enumerable

        attr_reader :decisions

        def initialize(decisions)
          @decisions = decisions
        end

        def each(&block)
          decisions.each(&block)
        end

        # The Decision for a single permission bit, e.g.
        # result[Constants::ACE::Mask::READ_DATA].
        def [](bit)
          decisions.find { |decision| decision.mask == bit }
        end

        # True when every requested bit was explicitly allowed.
        def permitted?
          decisions.all?(&:allowed?)
        end

        # True when at least one requested bit was explicitly denied.
        def denied?
          decisions.any?(&:denied?)
        end

        # True when at least one requested bit could not be decided from
        # the available data (missing ACL, unresolvable principal, or no
        # matching entry for that bit).
        def unknown?
          decisions.any?(&:unknown?)
        end
      end

      # Evaluate +acl+ for the subject identified by +user+ and +groups+
      # against the object owned by +owner+ (and optionally the owning
      # +group+), for every permission bit set in +mask+.
      #
      # +acl+ must be an array of entries responding to +type+, +flag+,
      # +mask+ and +who+ (such as Net::SFTP::Protocol::V04::Attributes::ACL),
      # in wire order. Returns a Result with one Decision per bit of +mask+.
      #
      # A bit is decided +:unknown+ when the ACL is +nil+ (the server did
      # not send one), when the subject cannot be resolved (+user+ or
      # +groups+ is +nil+), or when no applicable entry mentions the bit.
      def evaluate(acl:, user:, groups:, owner:, mask:, group: nil)
        bits = mask_bits(mask)

        if acl.nil? || user.nil? || groups.nil?
          return Result.new(bits.map { |bit| Decision.new(bit, :unknown, nil) })
        end

        decisions = bits.map do |bit|
          ace = acl.find do |entry|
            applicable?(entry) && (entry.mask & bit) != 0 &&
              matches?(entry, user, groups, owner, group)
          end

          if ace.nil?
            Decision.new(bit, :unknown, nil)
          elsif ace.type == Type::ACCESS_ALLOWED
            Decision.new(bit, :allow, ace)
          else
            Decision.new(bit, :deny, ace)
          end
        end

        Result.new(decisions)
      end

      # Compute the ACL that a newly created child of a directory would
      # inherit from the directory's +acl+. Pass +directory: true+ when the
      # child is itself a subdirectory.
      #
      # * FILE_INHERIT entries propagate to child files, DIRECTORY_INHERIT
      #   entries to child directories.
      # * INHERIT_ONLY is cleared on the inherited copy, so the entry takes
      #   effect on the child itself.
      # * NO_PROPAGATE_INHERIT entries are inherited by a child directory
      #   exactly once: the copy keeps its effect on the child but has its
      #   inheritance flags cleared, so it does not appear in grandchildren.
      # * Entries inherited by a plain file lose all inheritance flags, since
      #   a file has nothing to propagate to.
      #
      # The returned entries are new instances of the same class as the
      # originals; the input is not modified. Returns +nil+ when +acl+ is
      # +nil+.
      def inherit(acl, directory:)
        return nil if acl.nil?

        trigger = directory ? Flag::DIRECTORY_INHERIT : Flag::FILE_INHERIT

        acl.each_with_object([]) do |entry, inherited|
          next if (entry.flag & trigger) == 0

          flag = entry.flag & ~Flag::INHERIT_ONLY
          if directory
            if (entry.flag & Flag::NO_PROPAGATE_INHERIT) != 0
              flag &= ~(Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT |
                        Flag::NO_PROPAGATE_INHERIT)
            end
          else
            flag &= ~(Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT |
                      Flag::NO_PROPAGATE_INHERIT)
          end

          inherited << entry.class.new(entry.type, flag, entry.mask, entry.who)
        end
      end

      private

        # Audit and alarm entries record access attempts; they never grant
        # or revoke permissions. INHERIT_ONLY entries only apply to children
        # created later, never to the object carrying them.
        def applicable?(entry)
          (entry.type == Type::ACCESS_ALLOWED ||
            entry.type == Type::ACCESS_DENIED) &&
            (entry.flag & Flag::INHERIT_ONLY) == 0
        end

        def matches?(entry, user, groups, owner, group)
          case entry.who
          when OWNER
            user == owner
          when GROUP
            !group.nil? && groups.include?(group)
          when EVERYONE
            true
          else
            if (entry.flag & Flag::IDENTIFIER_GROUP) != 0
              groups.include?(entry.who)
            else
              entry.who == user
            end
          end
        end

        def mask_bits(mask)
          bits = []
          bit = 1
          while bit <= mask
            bits << bit if (mask & bit) != 0
            bit <<= 1
          end
          bits
        end
    end

  end
end
