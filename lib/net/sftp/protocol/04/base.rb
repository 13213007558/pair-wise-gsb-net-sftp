require 'net/sftp/protocol/03/base'
require 'net/sftp/protocol/04/attributes'
require 'net/sftp/protocol/04/name'

module Net; module SFTP; module Protocol; module V04

  # Wraps the low-level SFTP calls for version 4 of the SFTP protocol. Also
  # implements the updated FXP_NAME packet parsing as mandated by v4 of the
  # protocol.
  #
  # None of these protocol methods block--all of them return immediately,
  # requiring the SSH event loop to be run while the server response is
  # pending.
  #
  # You will almost certainly never need to use this driver directly. Please
  # see Net::SFTP::Session for the recommended interface.
  class Base < V03::Base

    # Returns the protocol version implemented by this driver. (4, in this
    # case)
    def version
      4
    end

    # Parses the version 4 and later FXP_STATUS packet format. The message and
    # language tag are optional when reading leniently so that a server using
    # the older short format still works.
    def parse_status_packet(packet)
      data = { :code => packet.read_long }

      unless packet.eof?
        data[:message] = packet.read_string
        data[:language] = packet.read_string unless packet.eof?
      end

      data
    end

    # As of v4 of the SFTP protocol, the "longname" member was removed from the
    # FXP_NAME structure. This method is essentially the same as the previous
    # implementation, but omits longname.
    def parse_name_packet(packet)
      names = []

      packet.read_long.times do
        filename = packet.read_string
        attrs    = attribute_factory.from_buffer(packet)
        names   << name_factory.new(filename, attrs)
      end

      { :names => names }
    end

    # Sends a FXP_STAT packet to the server for the given +path+, and with the
    # given +flags+. If +flags+ is nil, it defaults to F_SIZE | F_PERMISSIONS |
    # F_ACCESSTIME | F_CREATETIME | F_MODIFYTIME | F_ACL | F_OWNERGROUP |
    # F_SUBSECOND_TIMES | F_EXTENDED (see Net::SFTP::Protocol::V04::Attributes
    # for those constants).
    def stat(path, flags=nil)
      send_request(FXP_STAT, :string, path, :long, flags || DEFAULT_FLAGS)
    end

    # Sends a FXP_LSTAT packet to the server for the given +path+, and with the
    # given +flags+. If +flags+ is nil, it defaults to F_SIZE | F_PERMISSIONS |
    # F_ACCESSTIME | F_CREATETIME | F_MODIFYTIME | F_ACL | F_OWNERGROUP |
    # F_SUBSECOND_TIMES | F_EXTENDED (see Net::SFTP::Protocol::V04::Attributes
    # for those constants).
    def lstat(path, flags=nil)
      send_request(FXP_LSTAT, :string, path, :long, flags || DEFAULT_FLAGS)
    end

    # Sends a FXP_FSTAT packet to the server for the given +path+, and with the
    # given +flags+. If +flags+ is nil, it defaults to F_SIZE | F_PERMISSIONS |
    # F_ACCESSTIME | F_CREATETIME | F_MODIFYTIME | F_ACL | F_OWNERGROUP |
    # F_SUBSECOND_TIMES | F_EXTENDED (see Net::SFTP::Protocol::V04::Attributes
    # for those constants).
    def fstat(handle, flags=nil)
      send_request(FXP_FSTAT, :string, handle, :long, flags || DEFAULT_FLAGS)
    end

    protected

      # The default flags used if the +flags+ parameter is nil for any of the
      # #stat, #lstat, or #fstat operations.
      DEFAULT_FLAGS = Attributes::F_SIZE |
                      Attributes::F_PERMISSIONS |
                      Attributes::F_ACCESSTIME |
                      Attributes::F_CREATETIME |
                      Attributes::F_MODIFYTIME |
                      Attributes::F_ACL |
                      Attributes::F_OWNERGROUP |
                      Attributes::F_SUBSECOND_TIMES |
                      Attributes::F_EXTENDED

      # Returns the Attributes class used by this version of the protocol
      # (Net::SFTP::Protocol::V04::Attributes, in this case)
      def attribute_factory
        V04::Attributes
      end

      # Returns the Name class used by this version of the protocol
      # (Net::SFTP::Protocol::V04::Name, in this case)
      def name_factory
        V04::Name
      end
  end

end; end; end; end
