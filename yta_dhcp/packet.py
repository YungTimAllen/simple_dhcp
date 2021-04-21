"""DHCP Packet Tools"""
# Standard Imports
import struct
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum

# Project Imports
import yta_dhcp.util as util


FMTSTR_DHCP = "!ssss4s2s2s4s4s4s4s6s10s192s4s"


class DHCPPacketTypes(Enum):
    DHCPDISCOVER = 1  # [RFC2132]
    DHCPOFFER = 2  # [RFC2132]
    DHCPREQUEST = 3  # [RFC2132]
    DHCPDECLINE = 4  # [RFC2132]
    DHCPACK = 5  # [RFC2132]
    DHCPNAK = 6  # [RFC2132]
    DHCPRELEASE = 7  # [RFC2132]
    DHCPINFORM = 8  # [RFC2132]
    DHCPFORCERENEW = 9  # [RFC3203]
    DHCPLEASEQUERY = 10  # [RFC4388]
    DHCPLEASEUNASSIGNED = 11  # [RFC4388]
    DHCPLEASEUNKNOWN = 12  # [RFC4388]
    DHCPLEASEACTIVE = 13  # [RFC4388]
    DHCPBULKLEASEQUERY = 14  # [RFC6926]
    DHCPLEASEQUERYDONE = 15  # [RFC6926]
    DHCPACTIVELEASEQUERY = 16  # [RFC7724]
    DHCPLEASEQUERYSTATUS = 17  # [RFC7724]
    DHCPTLS = 18  # [RFC7724]


@dataclass()
class DHCPPacket:
    """Packet Payload Field Struct"""

    op: bytes
    htype: bytes
    hlen: bytes
    hops: bytes
    xid: bytes
    secs: bytes
    flags: bytes
    ciaddr: bytes
    yiaddr: bytes
    siaddr: bytes
    giaddr: bytes
    chaddr: bytes
    # padding HII192s
    _pad: bytes  # ..... We retain all padding so that dumping the object to bytes creates a
    _pad192s: bytes  # . bytearray which includes expected padding. See also: Deepcopy tasks
    magic: bytes
    options: bytes  # Should be loaded as "data[240 : len(data) - 1]" i.e. excluding END 0xFF
    end: bytes = bytes([0xFF])


def parse_packet(format_string: str, data: bytes) -> tuple:
    """Given raw dump of packets from wire representing a DHCP DISCOVER packet, and a well-known
    struct format-string, will read all fields and pack into a new DHCPPacket object

    Args:
        format_string: Well-known format string. See: yta_dhcp.packet.FormatStrings enum
        data: Raw bytes (bytearray) of length appropriate for given format_string

    Returns:
        DHCPPacket where attributes are loaded from given raw data, and dict containing options
    """

    raw_packet = struct.unpack(format_string, data[:240])

    packet = DHCPPacket(*raw_packet, options=data[240 : len(data) - 1])
    # end 0xff not needed
    options = parse_tlvs(packet.options)

    return packet, options


def parse_tlvs(data: bytes) -> dict:
    """Given a bytearray, will read from index 0, TLVs into a dict keyed "type: value"

    DHCP Options are TLVs in format 1 byte, 1 byte, 1+n bytes

    Args:
        data: bytearray containing TLVs

    Returns:
        Dict of TLVs, keyed by Type for associated Value. Length is discarded.
    """
    tlv_dict = {}
    i = 0
    while i < len(data):
        type_ = data[i]
        length = data[i + 1]
        value = data[i + 2 : i + 2 + length]

        tlv_dict[type_] = value
        i += 2 + length

    return tlv_dict


def dump_packet(dhcp_packet_obj: DHCPPacket) -> bytes:
    """Given a DHCPPacket object, will return it as a bytearray

    Args:
        dhcp_packet_obj: A DHCPPacket object

    Returns: Bytearray representing given DHCPPacket object

    """
    raw_packet = bytearray()
    for _, value in dhcp_packet_obj.__dict__.items():
        raw_packet += value

    return raw_packet


def generate_offer_packet(
    discover_packet: DHCPPacket, type_value:int, yiaddr: str, siaddr: str, yiaddr_mask: str
) -> DHCPPacket:
    """

    Args:
        discover_packet: DISCOVER DHCPPacket object loaded using yta_dhcp.packet.parse_packet
        yiaddr: IP to lease to calling client
        siaddr: DHCP Server IP address
        giaddr: Relay IP address
        yiaddr_mask: Subnet mask for leased IP

    Returns:
        OFFER DHCPPacket object
    """
    offer_packet = deepcopy(discover_packet)

    offer_packet.htype = type_value
    offer_packet.yiaddr = util.aton(yiaddr)
    offer_packet.siaddr = util.aton(siaddr)

    # todo options should be handled in their own object probably
    offer_packet.options = b"".join(
        [
            bytes([53, 1, DHCPPacketTypes.DHCPOFFER.value]),
            bytes([54, 4]) + util.aton(siaddr),
            bytes([51, 4, 0x00, 0x01, 0x51, 0x80]),
            bytes([1, 4]) + util.aton(yiaddr_mask),
            bytes([3, 4]) + offer_packet.giaddr,
        ]
    )

    return offer_packet
