// netsession.h
#pragma once
#include <pcap.h>
#include <exception>
#include <string>

class NetException: public std::exception {
public:
	NetException(const std::string& what){msg = what;}
	virtual ~NetException() throw(){}
	virtual const char* what() const throw(){return msg.c_str();}
private:
	std::string msg;
};

namespace Netpkt {
	struct Ether {
		Ether(){}
	};

	struct IP {
		IP(){}
	};

	struct TCP {
		TCP(){}
	};

	struct UDP {
		UDP(){}
	};

	struct ARP {
		ARP(){}
	};

	struct Packet {
		u_char* packet;
		unsigned int size;

		Packet(){}
		Packet(Ether eth){}
		Packet(Ether eth, IP ip){}
		Packet(Ether eth, ARP arp){}
	};
}

namespace Netssn {
	bool execute_shell(char* shell, char* res, int size);
	bool get_gateway_IP(Netpkt::IP ip);

	struct Session {
	private:
		pcap_t *mySession;
	public:
		Session(){}
		~Session(){}
		void open_session();
		void open_session(const char* device);
//		void send_packet(const char* packet, unsigned int size);
//		void send_packet(pkt::Packet packet);
//		void catch_packet();
//		void close_session();
	};
}
