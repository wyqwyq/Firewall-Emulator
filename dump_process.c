#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

int main(int argc, char **argv){
    if(argc != 3){
      fprintf(stdout, "Only need 2 Arguments.\nUsage: ./dump_process arg1 arg2\n");
      fprintf(stdout, "arg1: a time interval specified in seconds\n");
      fprintf(stdout, "arg2: the name of the dump file to save\n");
      exit(1);
    }
    time_t ti = atol(argv[1]);
    const char* fn = argv[2];
    const char * version = pcap_lib_version();
    fprintf(stdout, "************************\n%s\n************************\n", version);

    char errBuf[PCAP_ERRBUF_SIZE], * devStr;
    /* get a device */
    devStr = pcap_lookupdev(errBuf);
    if(devStr)  fprintf(stdout, "success: device: %s\n", devStr);
    else{
      fprintf(stderr, "error: %s\n", errBuf);
      exit(1);
    }
    time_t start, end, curTime;
    struct pcap_pkthdr *pktHeader;
    u_char * pktData;
    int status;
    time(&start);
    end = start + ti;
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 50, errBuf); /* wait for at most 50 millisecond */
    pcap_dumper_t * pd = pcap_dump_open(device, fn);
    while (curTime <= end){
        #if defined(_DEBUG_)
           fprintf(stdout, "status: %d\n", status);
        #endif
        status = pcap_next_ex(device, &pktHeader, (const u_char **)&pktData);
        if(status == 1){
          pcap_dump((u_char *)pd, pktHeader, pktData);
        }
        time(&curTime);
    }
    pcap_dump_close(pd);
    pcap_close(device);
    return 0;
}

