# Makefile
all : arp_spoofing

arp_spoofing : arp_spoofing.o netsession.o
	g++ -o arp_spoofing arp_spoofing.o netsession.o -lpcap

arp_spoofing.o : netsession.h arp_spoofing.cpp

netsession.o : netsession.h netsession.cpp

clean :
	rm -f arp_spoofing
	rm -f *.o
