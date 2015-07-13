#include "PacketManager.h"
#include "TCP_Conn.h"

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

#include <limits>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <string.h>
#include <utility>

using namespace std;

/*
The _dns_struct structure is based on the following DNS header.

                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/


typedef struct _dns_struct{
        unsigned short id;
        unsigned short flag;
        unsigned short ques;
        unsigned short answ;
        unsigned short auth;
        unsigned short addrrs;
} dns_struct;


bool isOutGoing_DNS_Query(dns_struct * ds){
	//QR = 0 && QDCOUNT == 0x0001 && ANCOUNT == 0 && NSCOUNT == 0
	return !(ntohs(ds->flag) >> 15) && ntohs(ds->ques) == 0x0001 && ntohs(ds->answ) == 0 && ntohs(ds->auth) == 0;
}

bool isOutGoing_DNS_Query(struct udphdr *uh){
	dns_struct * ds = (dns_struct *)((const u_char*)(uh) + sizeof(struct udphdr));
	return isOutGoing_DNS_Query(ds);
}

bool isOutGoing_DNS_Query(struct tcphdr *th){
	dns_struct * ds = (dns_struct *)((const u_char*)(th) + sizeof(struct tcphdr));
	return isOutGoing_DNS_Query(ds);
}


void displayTCP_Connection_Info(const u_char* packet){
	struct iphdr *ih = (struct iphdr *)(packet + sizeof(struct ether_header));
	struct tcphdr *th = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	char srcIP[20], dstIP[20];
	strcpy(srcIP, inet_ntoa(*(struct in_addr*)&(ih->saddr)) );
	strcpy(dstIP, inet_ntoa(*(struct in_addr*)&(ih->daddr)) );
	fprintf(stdout, "%s:%u ---TCP---> %s:%u\n", srcIP, ntohs(th->source), 
												dstIP, ntohs(th->dest) );
}

int printPktHeader(pcap_pkthdr *pktHeader)
{
    fprintf(stdout, "cap_time:%u, ", (unsigned int)pktHeader->ts.tv_sec);
    fprintf(stdout, "pkt length:%u, ", pktHeader->len);
    fprintf(stdout, "cap length:%u\n", pktHeader->caplen);
}

const uint16_t DNSPORT = 53;

PacketManager::PacketManager(string ip, string mac, int max_conn)
:max_conn_num(max_conn), localIP(ip), localMac(mac){
	
}

PacketManager::~PacketManager(){
	map<pair<string, string>, TCP_Conn*>::iterator it;
	for(it = m.begin(); it != m.end(); it++){
		delete it->second;
	}
}

void PacketManager::display_TCP_Conn(){
	int s;
	map<pair<string, string>, TCP_Conn*>::iterator it;
	for(it = m.begin(); it != m.end(); it++){
		s = it->second->getStatus();
		fprintf(stdout, "Connection: [%s] <---TCP---> [%s] status: %d\n", it->first.first.c_str(), it->first.second.c_str(), s);
	}
}

bool PacketManager::filter(pcap_pkthdr *pktHeader, const u_char* packet){
	struct ether_header *eptr; /* net/ethernet.h */
    eptr = (struct ether_header *) packet;
    if(ntohs(eptr->ether_type) == ETHERTYPE_IP) {
    	struct iphdr *ih = (struct iphdr *)(packet + sizeof(struct ether_header));
    	string dst = inet_ntoa(*(struct in_addr*)&(ih->daddr));
		string src = inet_ntoa(*(struct in_addr*)&(ih->saddr));
		
        if(ih->protocol == IPPROTO_UDP){ // udp
            struct udphdr *uh = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
             /*if(src == localIP && ntohs(uh->dest) == DNSPORT){
             	fprintf(stdout, "\nOutgoing DNS query is found: \n");
                fprintf(stdout, "src addr: %s\n", inet_ntoa(*(struct in_addr*)&(ih->saddr)));
                fprintf(stdout, "src port: %d\n", ntohs(uh->source));
                fprintf(stdout, "dest addr: %s\n", inet_ntoa(*(struct in_addr*)&(ih->daddr)));
                fprintf(stdout, "dest port: %d\n", ntohs(uh->dest));
                fprintf(stdout, "udp length: %d\n\n", ntohs(uh->len));
             	return true;
             }
            */
            // test if it's outgoing DNS Query
			if(isOutGoing_DNS_Query(uh)){
				fprintf(stdout, "\nOutgoing DNS query(UDP) is found:\n");
                fprintf(stdout, "src addr: %s\n", inet_ntoa(*(struct in_addr*)&(ih->saddr)));
                fprintf(stdout, "src port: %d\n", ntohs(uh->source));
                fprintf(stdout, "dest addr: %s\n", inet_ntoa(*(struct in_addr*)&(ih->daddr)));
                fprintf(stdout, "dest port: %d\n", ntohs(uh->dest));
                fprintf(stdout, "udp length: %d\n\n", ntohs(uh->len));				
             	return true;
			}
        }else if(ih->protocol == IPPROTO_TCP){
			struct tcphdr *th = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));			
			pair<string, string> key;
			string srcPort, dstPort;
			ss.clear();
			ss << ntohs(th->source);
			ss >> srcPort;
			string srcport = src + ":" + srcPort;
			ss.clear();
			ss << ntohs(th->dest);
			ss >> dstPort;
			string dstport = dst + ":" + dstPort;
			
			if(isOutGoing_DNS_Query(th)){
				fprintf(stdout, "\nOutgoing DNS query(TCP) is found:\n");
                fprintf(stdout, "src addr: %s\n", inet_ntoa(*(struct in_addr*)&(ih->saddr)));
                fprintf(stdout, "src port: %d\n", ntohs(th->source));
                fprintf(stdout, "dest addr: %s\n", inet_ntoa(*(struct in_addr*)&(ih->daddr)));
                fprintf(stdout, "dest port: %d\n", ntohs(th->dest));				
             	return true;
			}
			
			if(srcport <= dstport){
				key = make_pair(srcport, dstport);
			}else{
				key = make_pair(dstport, srcport);
			}
			
			if(src == localIP){ // indicates that this packet is outgoing
				if(m.count(key) == 0){ // not found in the map => this may be a new TCP connection, regardless of the max_conn_# restriction
					if((u_int16_t)(th->syn) !=0 && (u_int16_t)(th->ack) == 0){ // test if it's the first SYN packet
						m[key] = new TCP_Conn(src, dst, ntohs(th->source), ntohs(th->dest));
						m[key]->accept(packet);
						return s.size() >= max_conn_num;
					}
				}else{ // already recorded
					bool ret;
					bool previousNotEstablished = !m[key]->isEstablished();
					m[key]->accept(packet);
					if(previousNotEstablished && m[key]->isEstablished()){
						fprintf(stdout, "A new TCP connction is trying to establish. See the following info:\n");
						displayTCP_Connection_Info(packet);
						if(s.size() < max_conn_num){
							s.insert(m[key]);
							fprintf(stdout, "This connction is [accepted]. Now there are [%lu] connection(s)\n\n", s.size());
						}else{
							fprintf(stdout, "[Rejected] this connction is filtered out, since there are [%lu] connection(s) already\n\n", s.size());
						}
					}
					ret = s.count(m[key]) == 0;
					if(m[key]->isClosed()){
						if(s.count(m[key])){
						    fprintf(stdout, "A TCP connction is being destroyed.\n");
							displayTCP_Connection_Info(packet);
							s.erase(m[key]);
							fprintf(stdout, "Now there are [%lu] TCP connections\n\n", s.size());
						}
						delete m[key];
						m.erase(key);
					}
					return ret;
				}
			}else if(dst == localIP){ // indicates that this packet is incoming
				if(m.count(key) != 0){ //  must already recorded, otherwise we ignore it.
					m[key]->accept(packet);
					bool ret = s.size() >= max_conn_num && s.count(m[key]) == 0;
					if(m[key]->isClosed()){
						if(s.count(m[key])){
						    fprintf(stdout, "A TCP connction is being destroyed.\n");
							displayTCP_Connection_Info(packet);
							s.erase(m[key]);
							fprintf(stdout, "Now there are [%lu] TCP connections\n\n", s.size());
						}
						delete m[key];
						m.erase(key);
					}
					return ret;
				}
			}
        }
    }else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP) {
        fprintf(stdout, "\nARP packet is found: \n");
        printPktHeader(pktHeader);

        string srcMac;
        string destMac;
        char tmp[100];
        string local(localMac);

        u_char *ptr = eptr->ether_shost;
        int i = ETHER_ADDR_LEN;
        do {
            sprintf(tmp, "%s%02x",(i == ETHER_ADDR_LEN) ? "" : ":", *ptr++);  // attention:  " " -> "",  "%x" -> "02x"
            string str(tmp);
            srcMac += str;
        } while(--i>0);
		fprintf(stdout, "Source mac addr: %s\n", srcMac.c_str());		

        ptr = eptr->ether_dhost;
        i = ETHER_ADDR_LEN;
        do {
            sprintf(tmp, "%s%02x",(i == ETHER_ADDR_LEN) ? "" : ":", *ptr++); // attention:  " " -> "",  "%x" -> "02x"
            string str(tmp);
            destMac += str;
        } while(--i>0);
		fprintf(stdout, "Dest mac addr: %s\n", destMac.c_str());
       
        if(destMac == localMac || destMac == "ff:ff:ff:ff:ff:ff"){
        	fprintf(stdout, "filter out the ARP packet.\n\n");
        	return true; // incoming ARP packet found. This is what we need to filter out.
        }else{
        	fprintf(stdout, "\n");
        }
    }
    else if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP) {
        //fprintf(stdout,"(RARP)");
    }
    else if (ntohs (eptr->ether_type) == ETHERTYPE_SPRITE){
        //printf("SPRITE!\n");
    }
    else if (ntohs (eptr->ether_type) == ETHERTYPE_AT) {
        //printf("AT!\n");
    }
	else if (ntohs (eptr->ether_type) == ETHERTYPE_AARP) {
        //printf("AARP!\n");
    }
    else if (ntohs (eptr->ether_type) == ETHERTYPE_VLAN) {
        //printf("VLAN!\n");
    }
    else if (ntohs (eptr->ether_type) == ETHERTYPE_IPX) {
        //printf("IPX!\n");
    }
    else if (ntohs (eptr->ether_type) == ETHERTYPE_IPV6) {
        //printf("IPV6!\n");
    }
    else if (ntohs (eptr->ether_type) == ETHERTYPE_LOOPBACK) {
        //printf("LOOPBACK!\n");
    }
    return false;
}
