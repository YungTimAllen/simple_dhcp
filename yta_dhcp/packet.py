"""DHCP Packet Tools"""
# Standard Imports
import struct
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum

# Project Imports
import yta_dhcp.util as util


class FormatStrings(Enum):
    DISCOVER = "!ssss4s2s2s4s4s4s4s6s10s192s4s"
    OFFER = "!ssss4s2s2s4s4s4s4s6s10s192s4s"


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


def parse_packet(format_string: str, data: bytes) -> DHCPPacket:
    """Given raw dump of packets from wire representing a DHCP DISCOVER packet, and a well-known
    struct format-string, will read all fields and pack into a new DHCPPacket object

    Args:
        format_string: Well-known format string. See: yta_dhcp.packet.FormatStrings enum
        data: Raw bytes (bytearray) of length appropriate for given format_string

    Returns:
        DHCPPacket where attributes are loaded from given raw data
    """

    raw_packet = struct.unpack(format_string, data[:240])

    packet = DHCPPacket(*raw_packet, options=data[240 : len(data) - 1])
    # len-1 chops END byte 0xFF

    return packet


def dump_packet(dhcp_packet_obj: DHCPPacket) -> bytes:

    raw_packet = bytearray()
    for _, value in dhcp_packet_obj.__dict__.items():
        raw_packet += value

    return raw_packet


def generate_offer_packet(
    discover_packet: DHCPPacket, yiaddr: str, siaddr: str, yiaddr_mask: str
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

    offer_packet.htype = DHCPPacketTypes.DHCPOFFER.value
    offer_packet.yiaddr = util.aton(yiaddr)
    offer_packet.siaddr = util.aton(siaddr)

    # todo options should be handled in their own object probably
    offer_packet.options = b"".join(
        [
            bytes([53, 1, 2]),
            bytes([54, 4]) + util.aton(siaddr),
            bytes([51, 4, 0x00, 0x01, 0x51, 0x80]),
            bytes([1, 4]) + util.aton(yiaddr_mask),
            bytes([3, 4]) + util.aton(giaddr),
        ]
    )

    return offer_packet
