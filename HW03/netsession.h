// netsession.h
#pragma once
#include <exception>
#include <string>
#include <tins/tins.h>
#include <vector>

using namespace Tins;

class NetException: public std::exception {
public:
	NetException(const std::string& what){msg = what;}
	virtual ~NetException() throw(){}
	virtual const char* what() const throw(){return msg.c_str();}
private:
	std::string msg;
};

namespace Netssn {
	bool execute_shell(char* shell, char* res, int size);
	bool get_gateway_IP(std::string& oip, std::string& tip);
	bool get_my_config(std::string oip, std::string& ip, std::string& mac);
	bool convert_ip2mac(std::string ip, std::string& mac);

	struct Session {
	private:
		Sniffer* mySession;
		std::string myDevice;
		std::string myIP, myMAC, gtIP, gtMAC, vtIP, vtMAC;
	public:
		Session(){}
		Session(const unsigned packet_size);
		Session(const char* device, const unsigned packet_size);
		~Session(){}
		void set_config(std::string myIP_, std::string myMAC_,
				std::string gtIP_, std::string gtMAC_,
				std::string vtIP_, std::string vtMAC_){
			myIP = myIP_, myMAC = myMAC_;
			gtIP = gtIP_, gtMAC = gtMAC_;
			vtIP = vtIP_, vtMAC = vtMAC_;
		}
		void catch_packet(Packet &pkt);
		void catch_packet(std::vector<Packet> &pktvec,
				unsigned int size);
		void send_infection();
		bool is_recover_packet(Packet pkt);
		unsigned relay_packet(Packet pkt);
//		void close_session();
	};
}
