// send_arp.c
#include <pcap.h>
#include <stdio.h>
#include "pcaplib.h"

int main(int argc, char **argv){
	if(argc < 2){
		puts("Usage : sudo ./send_arp ip1.ip2.ip3.ip4");
		return 1;
	}

	int vic[4], gtw[4];
	if(sscanf(argv[1], "%d.%d.%d.%d", &vic[0], &vic[1], &vic[2], &vic[3]) != 4){
		puts("Invalid IP Type.");
		return 1;
	}
	if(getGatewayIP(gtw) < 0){
		puts("Failed to get Gateway's IP.");
		return 1;
	}

	sendFakePacket(vic, gtw);

//	opendevice(BUFSIZ, 0, argv[1]);
	return 0;
}

