### *Forked from [playma](https://github.com/playma/simple_dhcp)*

# Simple_dhcp

This DHCP server is written in Python3, and uses only the socket module

## Changes so far

* DISCOVER packet is inspected for relay source IP
* Transaction ID is passed to packet building functions

## Todo

- [ ] Formalise: I'll be using Google docstrings, Black, and PyLint
- [ ] Script should read from a settings file locally - Yaml
- [ ] Argparse and main()
- [ ] There are a lot of hardcoded values - figure out what should be hardcoded and what shouldnt
- [ ] Packet creation needs to be separated from the server logic
- [ ] What is the best way to build packets from just bytes? Probably some kind of bitmask struct, maybe from a class /shrug
- [ ] Just make it more modular

## Does it work?

Yes

Although values are hardcoded, it is observed to work for Cisco devices in a GNS3 lab. Topology is Server --- Relay(Cisco_7200) --- Client(Cisco_7200)

![R1 is the client router](https://i.imgur.com/0Y1YWNT.png)
