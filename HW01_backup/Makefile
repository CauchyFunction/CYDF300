# Makefile
all : pcap_test

pcap_test : pcap_test.o pcaplib.o
	gcc -o pcap_test pcap_test.o pcaplib.o -lpcap

pcap_test.o : pcaplib.h pcap_test.c

pcaplib.o : pcaplib.h pcaplib.c

clean :
	rm -f pcap_test
	rm -f *.o
