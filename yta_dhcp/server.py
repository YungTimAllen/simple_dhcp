"""Server"""
# Standard imports
import socket
from copy import deepcopy
import struct
import binascii
import ipaddress

# Project imports
import yta_dhcp.packet as packet


class DHCPServer:

    MAX_BYTES = 1024
    server_port = 67
    client_port = 68
    server_ip = "10.1.5.5"
    verbose = False

    def __init__(self, server_ip: str, verbose=False):
        self.server_ip = server_ip
        self.verbose = verbose

    def run(self):
        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        _socket.bind(("", self.server_port))

        while True:
            # try
            raw_discover_packet, relay_source = _socket.recvfrom(self.MAX_BYTES)

            discover_packet, _ = packet.parse_packet(
                packet.FMTSTR_DHCP, raw_discover_packet
            )

            offer_packet = packet.generate_offer_packet(
                discover_packet=discover_packet,
                type_value=packet.DHCPPacketTypes.DHCPOFFER.value,
                yiaddr="10.1.2.1",
                siaddr="10.1.5.5",
                yiaddr_mask="255.255.255.254",
            )
            raw_offer_packet = packet.dump_packet(offer_packet)

            _socket.sendto(raw_offer_packet, (relay_source[0], self.server_port))

            while True:
                raw_request_packet, relay_source = _socket.recvfrom(self.MAX_BYTES)

                _, _ = packet.parse_packet(packet.FMTSTR_DHCP, raw_request_packet)

                # Offer and Ack are identical, except for Type values in header and option 53
                ack_packet = deepcopy(offer_packet)
                ack_packet.htype = packet.DHCPPacketTypes.DHCPACK
                ack_packet.options[2] = packet.DHCPPacketTypes.DHCPACK
                raw_ack_packet = packet.dump_packet(ack_packet)

                _socket.sendto(raw_ack_packet, (relay_source[0], self.server_port))
