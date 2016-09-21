// pcaplib.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>

char ebuf[PCAP_ERRBUF_SIZE];

// https://wiki.kldp.org/KoreanDoc/html/Libpcap-KLDP/function.html : pcap.h functions
// close the port
void closedevice(pcap_t* pd){
	pcap_close(pd);
}

// open the port
void printer(u_char* dummy, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void opendevice(unsigned int bytes, unsigned int pktcnt){
	char* device;
	pcap_t* pd;

	device = pcap_lookupdev(ebuf);
	if(device == NULL) {puts(ebuf); exit(-1);}
	printf("%s\n", device);

	pd = pcap_open_live(device, bytes, 1/*PROMISCUOUS*/, -1, ebuf);
	if(pd == NULL){
		puts(ebuf);
		exit(-1);
	}
	puts("Port Opening Complete!");

	if(pcap_loop(pd, pktcnt, printer, NULL) < 0){
		puts("pcap simulating error!");
		closedevice(pd);
		exit(-1);
	}	
}

// http://www.joinc.co.kr/w/Site/Network_Programing/AdvancedComm/pcap_intro : packet analysis
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// get the packet
void printer(u_char* dummy, const struct pcap_pkthdr* pkthdr, const u_char* packet){
	struct ether_header *etherHdr;
	struct ip *ipHdr;
	struct tcphdr *tcpHdr;

	time_t ct = time(0);
	struct tm* now = localtime(&ct);
	printf("Packet Captured - %d-%d-%d %02d:%02d:%02d\n",
		1900+now->tm_year, 1+now->tm_mon, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);

	unsigned short ether_type;
	int length = pkthdr->len; int prnt = 0;

	// ethernet header
	etherHdr = (struct ether_header*) packet;
	printf("MAC     : %20s -> %20s\n", ether_ntoa(etherHdr->ether_shost), ether_ntoa(etherHdr->ether_dhost));

	// delete ethernet header
	packet += sizeof(struct ether_header);
	ether_type = ntohs(etherHdr->ether_type);

	// if header is ip type
	if(ether_type == ETHERTYPE_IP){
		ipHdr = (struct ip*) packet;

		// if header is tcp type
		if(ipHdr->ip_p == IPPROTO_TCP){
			tcpHdr = (struct tcp*)(packet + ipHdr->ip_hl*4); // ipHdr->ip_hl : header length, * 4byte
			printf("IP/PORT : %14s:%05d -> %14s:%05d\n", inet_ntoa(ipHdr->ip_src), ntohs(tcpHdr->source),
									inet_ntoa(ipHdr->ip_dst), ntohs(tcpHdr->dest));
		}
		else printf("IP/PORT : %14s:xxxxx -> %14s:xxxxx\n", inet_ntoa(ipHdr->ip_src), inet_ntoa(ipHdr->ip_dst));

		printf("CONTENT : ");
		while(length--){
			printf("%02X ", *(packet++));
			if((++prnt) % 16 == 0)printf("\n          ");
		}
		if(prnt % 16)puts("");
	}
	else puts("Non-IP Packet!");
	puts("");
}
