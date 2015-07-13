#ifndef TCP_CONN_H
#define TCP_CONN_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include<string>
using namespace std;

enum STATUS{
	CLOSED = 0,
	SYN_SENT,
	SYN_RECV,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_1_FIN_RECV,
	FIN_WAIT_1_FIN_ACK_RECV,
	FIN_WAIT_2_ACK_RECV,
	FIN_WAIT_2_FIN_RECV,
	CLOSING, // For the simultaneous shutting
	CLOSE_WAIT_FIN_RECV,
	CLOSE_WAIT,
	LAST_ACK,
	RST_RECV,
	RST_SENT,
	RST_CLOSING,
	RST_WAIT
};


class TCP_Conn{ // try to monitor the client-side status
public:
	TCP_Conn(string clientIP, string serverIP, unsigned int src_port, unsigned int dst_port);
	void accept(const u_char* packet);
	bool isEstablished();
	bool isClosed();
	STATUS getStatus();
private:
	string srcIP;
	string dstIP;
	unsigned int srcPort;
	unsigned int dstPort;
	
	STATUS status;
	
	unsigned long client_seq;
	unsigned long server_seq;
	
	
	bool checkACKNum(struct tcphdr *th, bool isClient);
	bool isSYNPacket(struct tcphdr *th);
	bool isACKPacket(struct tcphdr *th);
	bool isFINPacket(struct tcphdr *th);
	bool isRSTPacket(struct tcphdr *th);
	unsigned long get_data_length(const u_char* packet);
};

#endif
