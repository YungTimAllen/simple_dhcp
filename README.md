*Forked from [playma](https://github.com/playma/simple_dhcp)*

# yta_dhcp

This DHCP server is written in Python3, and tries to use native packages only

* Exceptions so far
  * PyYaml - For storing stuff, reading settings files, and quick dumping of pretty dicts
  * hexdump - For debugging
    
## Todo

- [x] Break off POC into Python package and call from main.py
- [x] Google docstrings, Black, PyLint
- [x] Argparse and script -> main()
- [x] Packet creation needs to be separated from the server logic
- [x] What is the best way to build packets from just bytes? (Answer: `struct.unpack`)
- [ ] Script should read from a settings file locally - Yaml
- [ ] There are a lot of hardcoded values - figure out what should be hardcoded and what shouldn't
- [ ] Implement some kind of database for recording leases
- [ ] Implement IP logic to make allocations from a given subnet

## Goals

What I want from this package is to solve all the problems I had previously been having from using massive and ugly 
dhcpd.conf files in isc-dhcpd-server. In my view, dhcpd.conf should be a yaml file.

## Does it work?

Yes - it only supports DORA - any other DHCP packet and it blows up

![R1 is the client router](https://i.imgur.com/0Y1YWNT.png)
