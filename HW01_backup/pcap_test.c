// pcap_test.c
#include <pcap.h>
#include "pcaplib.h"

int main(int argc, char **argv){
	char dev[150];
	getdevice(dev);
	puts(dev);
	opendevice(dev, BUFSIZ, 0);
	return 0;
}

