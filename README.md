# Overview
This is a project for a graduate-level course named CSDI(computer system design and implementation).

Bsically, it's a rundimentary emulator for firewall written in C++ with the Linux enviroment.

# Functions
* Dump packets to a pcap file using tcpdump
* Identify outgoing DNS queries and coming ARP requests
* Identify and monitor TCP connections' establishments and terminations, when the number of TCP connections exceed the upper limit, drop such packets.
* All the intermediate result will be recorded and output to a file or console . 

Note that it just emulates the behavior of real world firewall, but cannot do something real to the packets.


