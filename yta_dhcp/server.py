"""Server"""
# Standard imports
import socket
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

            discover_packet = packet.parse_packet(
                packet.FormatStrings.DISCOVER.value, raw_discover_packet
            )

            offer_packet = packet.generate_offer_packet(
                discover_packet=discover_packet,
                yiaddr="10.1.2.1",
                siaddr="10.1.5.5",
                yiaddr_mask="255.255.255.254",
            )
            raw_offer_packet = packet.dump_packet(offer_packet)

            _socket.sendto(raw_offer_packet, (relay_source[0], self.server_port))
