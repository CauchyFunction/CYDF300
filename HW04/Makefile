# Makefile
all : set_iptable modifyweb

set_iptable :
	sudo iptables -A INPUT -p tcp -j NFQUEUE --queue-num 0
	sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 1

modifyweb : modifyweb.o
	g++ -Wall -o modifyweb modifyweb.o -lnfnetlink -lnetfilter_queue

modifyweb.o : modifyweb.cpp

clean :
	sudo iptables -F
	rm -f modifyweb
	rm -f *.o
