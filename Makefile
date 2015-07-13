CC = gcc
GG = g++
CCFLAGS = -g -Wall
# LIBS = -lpcap -lssl -lcrypto
LIBS = -lpcap

all: dump_process packetsCollector firewall

dump_process: dump_process.c
	$(CC) $(CCFLAGS) -o $@ $<  $(LIBS)

firewall: firewall.cpp PacketManager.o TCP_Conn.o PacketManager.h TCP_Conn.h
	$(GG) -o $@ $^  $(LIBS)

PacketManager.o: PacketManager.cpp PacketManager.h
	$(GG) -c $^ $(LIBS)
	
TCP_Conn.o: TCP_Conn.cpp TCP_Conn.h
	$(GG) -c $^ $(LIBS)

packetsCollector: packetsCollector.c
	$(CC) -o $@ $< $(LIBS)

clean:
	rm -rf *.o dump_process packetsCollector firewall
	rm -rf *.txt
	
clear_dump:
	rm -rf *.pcap
