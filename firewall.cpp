#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h> 
#include <sys/ioctl.h>
#include "PacketManager.h"

char * getLocalIp(char * ip_buf){
	struct ifreq temp;
    struct sockaddr_in *myaddr;
    int fd = 0;
    int ret = -1;
    strcpy(temp.ifr_name, "eth0");
    if((fd=socket(AF_INET, SOCK_STREAM, 0))<0)
    {
        return NULL;
    }
    ret = ioctl(fd, SIOCGIFADDR, &temp);
    close(fd);
    if (ret < 0)
        return NULL;
    myaddr = (struct sockaddr_in *)&(temp.ifr_addr);
    strcpy(ip_buf, inet_ntoa(myaddr->sin_addr));
    return ip_buf;
}

void getLocalMacAddr(char localMacAddr[]) {
    struct ifreq tmp;
    int sock_mac;
    char mac_addr[30];
    sock_mac = socket(AF_INET, SOCK_STREAM, 0);
    if( sock_mac == -1)
    {
        perror("create socket fail\n");
        return;
    }
    memset(&tmp, 0, sizeof(tmp));
    strncpy(tmp.ifr_name, "eth0", sizeof(tmp.ifr_name)-1 );
    if( (ioctl( sock_mac, SIOCGIFHWADDR, &tmp)) < 0 )
    {
        fprintf(stdout, "mac ioctl error\n");
        return;
    }
    sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
            (unsigned char)tmp.ifr_hwaddr.sa_data[0],
            (unsigned char)tmp.ifr_hwaddr.sa_data[1],
            (unsigned char)tmp.ifr_hwaddr.sa_data[2],
            (unsigned char)tmp.ifr_hwaddr.sa_data[3],
            (unsigned char)tmp.ifr_hwaddr.sa_data[4],
            (unsigned char)tmp.ifr_hwaddr.sa_data[5]
            );
    close(sock_mac);
    memcpy(localMacAddr, mac_addr, strlen(mac_addr));
}

int main(int argc,char **argv)
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct pcap_pkthdr hdr; /* pcap.h */
	struct ether_header *eptr; /* net/ethernet.h */
	struct bpf_program fp; /* hold compiled program */
	bpf_u_int32 maskp; /* subnet mask */
	bpf_u_int32 netp; /* ip */
	char localMacAddr[30];
	
	if(argc != 4){
		fprintf(stdout,"Usage: %s \"input dump file\" \"max_connection_#\" \"output file\" \n", argv[0]);
		exit(1);
	}
	char ip_buf[20];
    char * localIP = getLocalIp(ip_buf);
    if(localIP == NULL){
    	fprintf(stdout, "getLocalIp(): Error\n");
		exit(1);
    }
	getLocalMacAddr(localMacAddr);
	descr = pcap_open_offline(argv[1] , errbuf);
	if(descr == NULL){
		fprintf(stdout, "pcap_open_offline(): %s\n",errbuf);
		exit(1);
	}
	
	int totalCnt = 0;
	int packetCnt = 0;
    pcap_pkthdr *pktHeader;
    int status;
    const u_char *pktData;
    u_char * args = NULL;
    fprintf(stdout, "IP: %s and max_tcp_# = %d\n", localIP, atoi(argv[2]));
	PacketManager pm(localIP, localMacAddr, atoi(argv[2]));
	if(access(argv[3], F_OK) != -1){
		fprintf(stdout, "The output dump file \"%s\" already exists. It will be overwritten.", argv[3]);
		if(unlink(argv[3]) != 0){
			fprintf(stderr, "Cannot delete the file \"%s\"\n", argv[3]);
			exit(1);
		}
	}
	pcap_dumper_t * pd = pcap_dump_open(descr, argv[3]);
    while(true){
        status = pcap_next_ex(descr, &pktHeader, &pktData);
        if(!pm.filter(pktHeader, pktData)){
        	pcap_dump((u_char *)pd, pktHeader, pktData);
        	packetCnt++;
        }
        if(status != 1)	break;
        totalCnt++;
    }
    pm.display_TCP_Conn();
    fprintf(stdout, "write totoally %d packets into %s, filtered out %.2lf%% packets.\n", packetCnt, argv[3], 
    				(double)((totalCnt - packetCnt)*100)/totalCnt);
    pcap_dump_close(pd);
	pcap_close(descr);
	return 0;
}
