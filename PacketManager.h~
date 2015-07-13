#ifndef PACKET_MANAGER_H
#define PACKET_MANAGER_H

#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <sstream>

using namespace std;

class TCP_Conn;

class PacketManager{
public:
	PacketManager(string ip, string mac, int max_conn = numeric_limits<int>::max());
	~PacketManager();
	
	bool filter(pcap_pkthdr *pktHeader, const u_char* packet);
	
	void display_TCP_Conn();

private:
	string localIP;
	string localMac;
	int max_conn_num;
	map<pair<string, string>, TCP_Conn*> m;
	set<TCP_Conn *> s;
	stringstream ss;
};

#endif
