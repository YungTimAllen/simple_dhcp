#!/usr/bin/env python3
import socket

MAX_BYTES = 1024

serverPort = 67
clientPort = 68


class DHCP_server(object):
    def server(self):
        print("DHCP server is starting...\n")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", serverPort))
        dest = ("255.255.255.255", clientPort)

        while 1:
            try:
                print("Wait DHCP discovery.")
                data, address = s.recvfrom(MAX_BYTES)
                print("Receive DHCP discovery.")

                # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
                # print(bytes(data).hex())
                packet_bytes = [data[i : i + 1] for i in range(len(data))]
                print([b.hex() for b in packet_bytes])
                relay_source = (
                    f"{str(int.from_bytes(packet_bytes[24], 'little'))}."
                    f"{str(int.from_bytes(packet_bytes[25], 'little'))}."
                    f"{str(int.from_bytes(packet_bytes[26], 'little'))}."
                    f"{str(int.from_bytes(packet_bytes[27], 'little'))}"
                )

                tx_id = b"".join(packet_bytes[4:8])

                print(relay_source)

                print("Send DHCP offer.")
                data = DHCP_server.offer_get(tx_id=tx_id)
                s.sendto(data, (relay_source, serverPort))

                # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

                while 1:
                    try:
                        print("Wait DHCP request.")
                        data, address = s.recvfrom(MAX_BYTES)
                        print("Receive DHCP request.")
                        # print(data)

                        print("Send DHCP pack.\n")
                        data = DHCP_server.pack_get(tx_id=tx_id)
                        s.sendto(data, (relay_source, serverPort))
                        break
                    except:
                        raise
            except:
                raise

    def offer_get(tx_id):

        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x01])
        XID = tx_id
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x80, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        # YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])  # 192.168.1.100
        YIADDR = bytes([0x0A, 0x01, 0x02, 0x01])  # 10.1.2.1
        # SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1
        SIADDR = bytes([0x0A, 0x01, 0x05, 0x05])  # 10.1.5.5
        # GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
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

    def pack_get(tx_id):
        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x01])
        XID = tx_id
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x80, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        # YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])  # 192.168.1.100
        YIADDR = bytes([0x0A, 0x01, 0x02, 0x01])  # 10.1.2.1
        # SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1
        SIADDR = bytes([0x0A, 0x01, 0x05, 0x05])  # 10.1.5.5
        # GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
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


if __name__ == "__main__":
    dhcp_server = DHCP_server()
    dhcp_server.server()
