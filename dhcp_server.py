#!/usr/bin/env python3
"""Python implementation of a DHCP server, to serve clients behind a DHCP relay

Notes:
    https://docs.microsoft.com/en-us/windows-server/troubleshoot/dynamic-host-configuration-protocol-basics
    https://docs.python.org/3/library/struct.html#format-characters
"""
import socket
import struct
import binascii


import hexdump as hexdump

# todo move this into some kind of class
def mtob(chaddr: str) -> bytes:
    return binascii.unhexlify(chaddr.replace(":", ""))


class DHCPServer:
    """DHCP Server, to include socket estab, packet.py processing, and DORA"""

    MAX_BYTES = 1024
    serverPort = 67
    clientPort = 68
    serverIP = "10.1.5.5"

    def server(self):
        """Main method for this class. Includes blocking logic to capture packets"""
        print("DHCP server is starting...\n")

        _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        _socket.bind(("", self.serverPort))

        while 1:
            try:
                print("Wait DHCP discovery.")

                data, _ = _socket.recvfrom(self.MAX_BYTES)
                # Second var was prev called "address"

                print("Receive DHCP discovery.")

                # Load UDP packet.py payload to list<bytes>
                packet_bytes = [data[i : i + 1] for i in range(len(data))]
                # print([b.hex() for b in packet_bytes])

                # Relay IP Address (giaddr)
                relay_source = (
                    f"{str(int.from_bytes(packet_bytes[24], 'little'))}."
                    f"{str(int.from_bytes(packet_bytes[25], 'little'))}."
                    f"{str(int.from_bytes(packet_bytes[26], 'little'))}."
                    f"{str(int.from_bytes(packet_bytes[27], 'little'))}"
                )
                # print(relay_source)

                # Transaction ID (xid)
                tx_id = b"".join(packet_bytes[4:8])
                # todo b"".join() is neat - where else can we do it? Private method?
                # print(tx_id)

                print("Send DHCP offer.")

                data = self.offer_get(tx_id=tx_id)
                _socket.sendto(data, (relay_source, self.serverPort))

                # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

                while 1:
                    try:
                        print("Wait DHCP request.")
                        data, address = _socket.recvfrom(self.MAX_BYTES)
                        print("Receive DHCP request.")
                        # print(data)

                        print("Send DHCP pack.\n")
                        data = self.ack_get(tx_id=tx_id)
                        _socket.sendto(data, (relay_source, self.serverPort))
                        break
                    except:
                        raise
            except:
                raise

    # todo packet.py building should be in separate classes probably
    def offer_get(self, tx_id: bytes) -> bytes:
        """Create DHCP OFFER packet.py

        Args:
            tx_id: Transaction id

        Returns:
            bytes object representing the OFFER packet.py
        """

        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x01])
        XID = tx_id
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x80, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x0A, 0x01, 0x02, 0x01])  # 10.1.2.1
        SIADDR = bytes([0x0A, 0x01, 0x05, 0x05])  # 10.1.5.5
        GIADDR = bytes([0x0A, 0x01, 0x02, 0x00])  # 10.1.2.0
        CHADDR1 = bytes([0xCA, 0x02, 0x8D, 0xBF])
        CHADDR2 = bytes([0x00, 0x08, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 2])  # DHCP pky type is Offer
        DHCPOptions5 = bytes([54, 4, 0x0A, 0x01, 0x05, 0x05])  # DHCP server ip
        DHCPOptions4 = bytes(
            [51, 4, 0x00, 0x01, 0x51, 0x80]
        )  # 86400s(1 day) IP address lease time
        DHCPOptions2 = bytes(
            [1, 4, 0xFF, 0xFF, 0xFF, 0xFE]
        )  # 255.255.255.254 subnet mask
        DHCPOptions3 = bytes([3, 4, 0x0A, 0x01, 0x02, 0x00])  # gw, same as relay source

        END = bytes([0xFF])

        package = (
            OP
            + HTYPE
            + HLEN
            + HOPS
            + XID
            + SECS
            + FLAGS
            + CIADDR
            + YIADDR
            + SIADDR
            + GIADDR
            + CHADDR1
            + CHADDR2
            + CHADDR3
            + CHADDR4
            + CHADDR5
            + Magiccookie
            + DHCPOptions1
            + DHCPOptions2
            + DHCPOptions3
            + DHCPOptions4
            + DHCPOptions5
            + END
        )

        return package

    # todo the only way these params will ever get populated is after DISC is parsed by unpack
    # so theres no reason to make them strings - keep them bytes like tx_id
    def offer_get_2(
        self,
        tx_id: bytes,
        yiaddr: str,
        yiaddr_mask: str,
        siaddr: str,
        giaddr: str,
        chaddr: str,
    ) -> bytes:
        """

        Args:
            tx_id:
            ciaddr:
            yiaddr:
            siaddr:
            giaddr:
            chaddr:
            yiaddr_mask:

        Returns:

        """
        # Op Code (op) = 2 (0x2)
        # Hardware Type (htype) = 1 (0x1) 10Mb Ethernet
        # Hardware Address Length (hlen) = 6 (0x6)
        # Hops (hops) = 0 (0x0)
        # Transaction ID (xid) = 556223005 (0x21274A1D)
        # Seconds (secs) = 0 (0x0)
        # Flags (flags) = 0x8000
        # Client IP Address (ciaddr) (Not used in DORA)
        # Your IP Address (yiaddr)
        # Server IP Address (siaddr)
        # Relay IP Address (giaddr)
        # MAC address
        # 10 bytes of padding
        # 192 bytes of padding
        # "Magic cookie"
        p_a = struct.pack(
            "!BBBB4sHHI4s4s4s6sHII192sI",
            0x2,
            0x1,
            0x6,
            1,
            tx_id,
            0x0000,
            0x8000,
            0x00000000,
            socket.inet_aton(yiaddr),
            socket.inet_aton(siaddr),
            socket.inet_aton(giaddr),
            mtob(chaddr),
            0x0000,
            0x00000000,
            0x00000000,
            bytearray(192),
            0x63825363,
        )

        # todo options should be passed as parameter?
        options = [
            bytes([53, 1, 2]),
            bytes([54, 4, 0x0A, 0x01, 0x05, 0x05]),
            bytes([51, 4]) + socket.inet_aton(self.serverIP),
            bytes([1, 4]) + socket.inet_aton(yiaddr_mask),
            bytes([3, 4]) + socket.inet_aton(giaddr),
        ]

        end = bytes([0xFF])

        return p_a + b"".join(options) + end

    def ack_get(self, tx_id: bytes) -> bytes:
        """Create DHCP ACK packet.py

        Args:
            tx_id: Transaction id

        Returns:
            bytes object representing the ACK packet.py
        """
        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x01])
        XID = tx_id
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x80, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x0A, 0x01, 0x02, 0x01])  # 10.1.2.1
        SIADDR = bytes([0x0A, 0x01, 0x05, 0x05])  # 10.1.5.5
        GIADDR = bytes([0x0A, 0x01, 0x02, 0x00])  # 10.1.2.0
        CHADDR1 = bytes([0xCA, 0x02, 0x8D, 0xBF])
        CHADDR2 = bytes([0x00, 0x08, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 5])  # DHCP ACK(value = 5)
        DHCPOptions5 = bytes([54, 4, 0x0A, 0x01, 0x05, 0x05])  # DHCP server ip
        DHCPOptions4 = bytes(
            [51, 4, 0x00, 0x01, 0x51, 0x80]
        )  # 86400s(1 day) IP address lease time
        DHCPOptions2 = bytes(
            [1, 4, 0xFF, 0xFF, 0xFF, 0xFE]
        )  # 255.255.255.254 subnet mask
        DHCPOptions3 = bytes([3, 4, 0x0A, 0x01, 0x02, 0x00])  # gw, same as relay source
        END = bytes([0xFF])

        package = (
            OP
            + HTYPE
            + HLEN
            + HOPS
            + XID
            + SECS
            + FLAGS
            + CIADDR
            + YIADDR
            + SIADDR
            + GIADDR
            + CHADDR1
            + CHADDR2
            + CHADDR3
            + CHADDR4
            + CHADDR5
            + Magiccookie
            + DHCPOptions1
            + DHCPOptions2
            + DHCPOptions3
            + DHCPOptions4
            + DHCPOptions5
            + END
        )

        return package


class DHCP_Packet:
    def __init__(self, src_host, src_port, dst_host, dst_port, flags=0):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.flags = flags


if __name__ == "__main__":
    dhcp_server = DHCPServer()

    hexdump.hexdump(
        dhcp_server.offer_get_2(
            bytes.fromhex("FEFEFEFE"),
            "10.1.2.1",
            "255.255.255.254",
            "10.1.5.5",
            "10.1.2.0",
            "aa:bb:cc:dd:ee:ff",
        )
    )
    print("-" * 64)

    dhcp_server.server()
