*Forked from [playma](https://github.com/playma/simple_dhcp)*

# yta_dhcp

This DHCP server is written in Python3, and tries to use native packages only

* Exceptions so far
  * PyYaml - For storing stuff, reading settings files, and quick dumping of pretty dicts
  * hexdump - For debugging
    
## Todo

- [x] Break off POC into Python package and call from main.py
- [x] Formalise: I'll be using Google docstrings, Black, and PyLint
- [ ] Script should read from a settings file locally - Yaml
- [x] Argparse and script -> main()
- [ ] There are a lot of hardcoded values - figure out what should be hardcoded and what shouldnt
- [x] Packet creation needs to be separated from the server logic
- [x] What is the best way to build packets from just bytes? (Answer: `struct.unpack`)
- [ ] Implement some kind of database for recording leases
- [ ] Implement IP logic to make allocations from a given subnet

## Goals

What I want from this package is to solve all the problems I had previously been having from using massive and ugly 
dhcpd.conf files in isc-dhcpd-server. In my view, dhcpd.conf should be a yaml file.

Building the solution in Python and as a Package also means you can just spawn a DHCP server and start its logic from
within any Python app, and that will ideally mean passing methods that the server's logic should call on certain
events. An easily programmable, event-driven DHCP server.

## Does it work?

Yes

Although values are hardcoded, it is observed to work for Cisco devices in a GNS3 lab. 

Topology is Server --- Relay(Cisco_7200) --- Client(Cisco_7200)

![R1 is the client router](https://i.imgur.com/0Y1YWNT.png)
