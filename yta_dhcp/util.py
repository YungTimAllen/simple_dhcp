"""DHCP Utilities"""
import socket
import struct
import binascii
import hexdump


def mtob(chaddr: str) -> bytes:
    """Takes a MAC address in 5-colon-format and returns bytearray

    Examples:
        Given 'aa:bb:cc:dd:ee:ff', will return b'\xaa\xbb\xcc\xdd\xee\xff'

    Args:
        chaddr:

    Returns:

    """
    return binascii.unhexlify(chaddr.replace(":", ""))


def aton(iaddr: str) -> bytes:
    """Takes an IP address in 4 octet format and returns bytearray"""
    return socket.inet_aton(iaddr)


def ntoa(iaddr: bytes) -> str:
    """Takes an IP address in bytes format and returns string"""
    return f"{iaddr[0]}.{iaddr[1]}.{iaddr[2]}.{iaddr[3]}"


def read_hexdump_file(filename: str) -> bytes:
    """Debugging method reads hexdumps from a file

    Examples:
        Expected input is space-delimited 16-column single bytes

    Args:
        filename: txt file containing

    Returns:
        bytearray with contents hex from file as bytes
    """
    with open(filename, "r") as _fp:
        data = bytearray()
        for line in _fp.readlines():
            data += bytearray.fromhex(line.replace(" ", ""))

    return data


def hexdump_(data: bytearray):
    """Hexdump print to cli given data"""
    hexdump.hexdump(data)
