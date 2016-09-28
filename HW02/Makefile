# Makefile
all : send_arp

send_arp : send_arp.o pcaplib.o
	gcc -o send_arp send_arp.o pcaplib.o -lpcap

send_arp.o : pcaplib.h send_arp.c

pcaplib.o : pcaplib.h pcaplib.c

clean :
	rm -f send_arp
	rm -f *.o
