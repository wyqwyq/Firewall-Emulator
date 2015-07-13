#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "TCP_Conn.h"
#include <string>

using namespace std;

TCP_Conn::TCP_Conn(string clientIP, string serverIP, unsigned int src_port, unsigned int dst_port)
:srcIP(clientIP), dstIP(serverIP), srcPort(src_port), dstPort(dst_port), status(CLOSED){

}

STATUS TCP_Conn::getStatus(){
	return status;
}

bool TCP_Conn::isEstablished(){
	return status == ESTABLISHED;
}

bool TCP_Conn::isClosed(){
	return status == CLOSED;
}

bool TCP_Conn::isSYNPacket(struct tcphdr *th){
	return (u_int16_t)(th->syn) != 0;
}

bool TCP_Conn::isACKPacket(struct tcphdr *th){
	return (u_int16_t)(th->ack) != 0;
}

bool TCP_Conn::isFINPacket(struct tcphdr *th){
	return (u_int16_t)(th->fin) != 0;
}

bool TCP_Conn::isRSTPacket(struct tcphdr *th){
	return (u_int16_t)(th->rst) != 0;
}

unsigned long TCP_Conn::get_data_length(const u_char* packet){
	struct iphdr *ih = (struct iphdr *)(packet + sizeof(struct ether_header) );
	struct tcphdr *th = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	return ntohs(ih->tot_len) - ( ih->ihl +  th->doff) * 4;
}

bool TCP_Conn::checkACKNum(struct tcphdr *th, bool isClient){
	if(isClient){
		return ntohl(th->ack_seq) == client_seq;
	}else{
		return ntohl(th->ack_seq) == server_seq;
	}
}

void TCP_Conn::accept(const u_char* packet){
	struct iphdr *ih = (struct iphdr *)(packet + sizeof(struct ether_header) );
	struct tcphdr *th = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	string dst = inet_ntoa(*(struct in_addr*)&(ih->daddr));
	string src = inet_ntoa(*(struct in_addr*)&(ih->saddr));
	if(dst == dstIP){ // The packet is outgoing
		client_seq = ntohl(th->seq) + get_data_length(packet);
		if(isSYNPacket(th) || isFINPacket(th)){
			client_seq++;
		}
		switch(status){
		case CLOSED:
			if(isSYNPacket(th) && !isACKPacket(th)){
				status = SYN_SENT;
			}
			break;
		case SYN_RECV:
			if(isACKPacket(th) && checkACKNum(th, false)){
				// A new TCP connection now is created.
				status = ESTABLISHED;
			}else if(isRSTPacket(th)){
				status = CLOSED;
			}
			break;
		case ESTABLISHED:
			if(isFINPacket(th)){
				status = FIN_WAIT_1;
			}else if(isRSTPacket(th)){
				status = RST_SENT;
			}
			break;
		
		case FIN_WAIT_2_FIN_RECV:
			if((isACKPacket(th) && checkACKNum(th, false)) || isRSTPacket(th)){
				// The TCP connection now is destroyed.
				status = CLOSED;
			}
			break;
		
		case FIN_WAIT_1:
			if(isRSTPacket(th)){
				status = RST_SENT;
			}
			break;
		case FIN_WAIT_1_FIN_RECV:
			if(isACKPacket(th) && checkACKNum(th, false)){
				status = CLOSING;
			}
			break;
		case FIN_WAIT_1_FIN_ACK_RECV:
			if(isACKPacket(th) && checkACKNum(th, false)){
				// The TCP connection now is destroyed.
				status = CLOSED;
			}
			break;
		case FIN_WAIT_2_ACK_RECV:
			if(isRSTPacket(th)){
				//status = RST_SENT;
				status = CLOSED;				
			}
			break;
		case CLOSE_WAIT_FIN_RECV:
			if((isACKPacket(th) && checkACKNum(th, false)) && !isFINPacket(th)){
				status = CLOSE_WAIT;
			}else if((isACKPacket(th) && checkACKNum(th, false)) && isFINPacket(th)){
				status = LAST_ACK;
			}
			break;
		case CLOSE_WAIT:
			if(isFINPacket(th)){
				status = LAST_ACK;
			}
			break;
		case RST_CLOSING:
			if(isRSTPacket(th)){
				// The TCP connection now is destroyed.
				status = CLOSED;
			}
			break;
		case RST_RECV:
			if(isFINPacket(th)){
				status = RST_WAIT;
			}
			break;
		default:
			break;
		}
	}else if(src == dstIP){ // The packet is incoming
		server_seq = ntohl(th->seq) + get_data_length(packet);
		if(isSYNPacket(th) || isFINPacket(th)){
			server_seq++;
		}
		
		switch(status){
		case SYN_SENT:
			if(isSYNPacket(th) ){
				if((isACKPacket(th) && checkACKNum(th, true)))
					status = SYN_RECV;
			}else if(isRSTPacket(th)){
				status = CLOSED;
			}
			break;
		case ESTABLISHED:
			if(isFINPacket(th)){
				status = CLOSE_WAIT_FIN_RECV;
			}else if(isRSTPacket(th)){
				status = RST_RECV;
			}
			break;
		case FIN_WAIT_1:
			if((isACKPacket(th) && checkACKNum(th, true))&& !isFINPacket(th)){
				status = FIN_WAIT_2_ACK_RECV;
			}else if(!isACKPacket(th) && isFINPacket(th)){
				status = FIN_WAIT_1_FIN_RECV;
			}else if((isACKPacket(th) && checkACKNum(th, true)) && isFINPacket(th)){
				status = FIN_WAIT_1_FIN_ACK_RECV;
			}
			break;
		case FIN_WAIT_2_ACK_RECV:
			if(isFINPacket(th)){
				status = FIN_WAIT_2_FIN_RECV;
			}
			break;
		case CLOSING:
			if(isACKPacket(th) && checkACKNum(th, true)){
				// The TCP connection now is destroyed.
				status = CLOSED;
			}
			break;
		case LAST_ACK:
			if(isACKPacket(th) && checkACKNum(th, true)){
				// The TCP connection now is destroyed.
				status = CLOSED;
			}
			break;
		case RST_SENT:
			if(isFINPacket(th)){
				status = RST_CLOSING;
			}
			break;
		case RST_WAIT:
			if(isRSTPacket(th)){
				// The TCP connection now is destroyed.
				status = CLOSED;
			}
			break;
		case CLOSE_WAIT:
			if(isRSTPacket(th)){
				status = RST_RECV;
			}
			break;
		default:
			break;
		}	
	}
}








