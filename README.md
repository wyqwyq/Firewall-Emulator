# Overview
This is a project for a graduate-level course named CSDI(computer system design and implementation).

Bsically, it's a rundimentary emulator for firewall written in C++ with the Linux enviroment.

# Functions
* Dump packets to a pcap file using *tcpdump*
* Identify outgoing DNS queries and coming ARP requests
* Identify and monitor TCP connections' establishments and terminations, when the number of TCP connections exceed the upper limit, drop such packets.
* All the intermediate result will be recorded and output to a file or console . 

Note that it just emulates the behavior of real world firewall, but cannot do something real to the packets.

# Main Solutions
* To identify Incoming ARP Packets, the following two must be met:
    1. ARP packet 
    2. Broadcast (dest MAC Addr is FF:FF:FF:FF:FF:FF) Or dest MAC address equals to local MAC Addr
* To identify Outgoing DNS Query, parse the DNS datagram and check whether QR = 0 && QDCOUNT == 0x0001 && ANCOUNT == 0 && NSCOUNT == 0.
* Identify Outgoing TCP Connection: In general, we use state machine to keep track of outgoing TCP connection. This can be divided into  2 parts: 
    1. Identify TCP Connection Establishment
        ![Normal establishment](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img1.jpg "Normal establishment")
        ![Exceptional establishment](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img2.jpg "Exceptional establishment")
        ![Exceptional establishment](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img3.jpg "Exceptional establishment")
    2. Identify TCP Connection Termination
        * Normal termination (Active/Passive)
![Normal termination Active](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img4.jpg "Normal termination Active")
![Normal termination Passive](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img5.jpg "Normal termination Passive")
        * Simultaneous termination (rarely happen)
![Simultaneous termination](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img6.jpg "Simultaneous termination")
        * Exceptional termination--Active(passive is similar, not displayed)
![Exceptional termination Active 1](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img7.jpg "Exceptional termination Active 1")
![Exceptional termination Active 2](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img8.jpg "Exceptional termination Active 2")
![Exceptional termination Active 3](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img9.jpg "Exceptional termination Active 9")
![Exceptional termination Active 4](https://github.com/wyqwyq/Firewall-Emulator/blob/master/img10.jpg "Exceptional termination Active 4")

