#!/usr/bin/env python3
"""x"""
# Standard imports
from argparse import ArgumentParser, Namespace
import yaml

# Project imports
import yta_dhcp


def main(parser: Namespace):
    """Entry point when ran as a script"""

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # Dev and debugging

    server = yta_dhcp.server.DHCPServer("10.1.5.5")
    server.run()


def testing():

    # Debug tools under yta_dhcp.util allow to load raw DHCP packets from file
    # - See method docstring to format required on hex dump
    t_disc = yta_dhcp.util.read_hexdump_file(filename="samples/DISCOVER")

    # Format strings for readable packet types are stored in enum yta_dhcp.packet.FormatStrings
    fmt_string = yta_dhcp.packet.FMTSTR_DHCP

    # parse_packet will take a format string and raw data. It'll unpack values from data to a DHCP
    # packet object, where packet fields are attributes and values are present (as raw Bytes)
    p_disc, options = yta_dhcp.packet.parse_packet(fmt_string, t_disc)

    # for key, value in p_disc.__dict__.items():
    #    print(f"{key}\t{value}")

    # Compare the data loaded from file to what was parsed and packed into our object
    print("Magic == 0x63825363?\t", f"0x{p_disc.magic.hex()}" == "0x63825363")
    print("Pre and Post data equal?\t", yta_dhcp.dump_packet(p_disc) == t_disc)

    # Testing ntoa

    print(yta_dhcp.util.ntoa(bytes([0x0A, 0x01, 0x02, 0x01])))

    # Testing options
    print(options)


if __name__ == "__main__":
    params = ArgumentParser(description="DHCP Server")
    params.add_argument("--pass", help="dummy arg")

    main(params.parse_args())
