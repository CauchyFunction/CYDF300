// HW4 : Modifying Web Browser
// This Code is Motivated From "libnetfilter_queue-1.0.2/utils/nfqnl_test.c"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

int quenum = 0;

void addBytes(unsigned char *a, unsigned char *b){ // a += b
	unsigned int a2 = (a[0]<<8)|a[1], b2 = (b[0]<<8)|b[1];
//	printf("%04X %04X\n", a2, b2);
	a2 += b2;
	if(a2 & 1<<16)a2++;
	a2 &= 0xFFFF;
	a[0] = (unsigned char) (a2>>8), a[1] = (unsigned char) a2&0xFF;
}

void addByteInt(unsigned char *a, unsigned int b){ // a += b
	unsigned int a2 = (a[0]<<8)|a[1];
//	printf("%04X %04X\n", a2, b);
	a2 += b;
	if(a2 & 1<<16)a2++;
	a2 &= 0xFFFF;
	a[0] = (unsigned char) (a2>>8), a[1] = (unsigned char) a2&0xFF;
}

void getTCPHeader(unsigned char *pdata, unsigned int plen){
	unsigned int i;
	unsigned char psd[2]={0,0}, tcp[2]={0,0};
	pdata[36] = pdata[37] = 0;

	for(i=12; i<=18; i+=2)addBytes(psd, &pdata[i]); // src ip, dst ip
	addByteInt(psd, 0x0006), addByteInt(psd, plen-20); // protocol #, TCP length
//	printf("psd : %02X%02X\n", psd[0], psd[1]);

	for(i=20; i<plen; i+=2)addBytes(tcp, &pdata[i]); // all of tcp segments
//	printf("tcp : %02X%02X\n", tcp[0], tcp[1]);
	addBytes(psd, tcp); // pseudo header + tcp segment

	psd[0] ^= 0xFF, psd[1] ^= 0xFF; // complement of 1
	pdata[36] = psd[0], pdata[37] = psd[1];
	// 0~19 : ip header, 20~39 : tcp header (36~37 : checksum), 40~ : data
}

int changePacket(unsigned char *pdata, unsigned int plen, const char* fnd, const char* rpl, unsigned int len){
	int fl = 0;
	if(plen > 20 && pdata[9] == 0x06){ // first 20 bytes are IP Header & TCP
		for(unsigned int i=20; i<=plen-len; i++){
			unsigned int j;
			for(j=0; j<len; j++){
				if(pdata[i+j] != (unsigned char) fnd[j])break;
			}
			if(j==len){
				for(j=0; j<len; j++)pdata[i+j] = (unsigned char) rpl[j];
				i+=len-1; fl=1;
			}
		}
		getTCPHeader(pdata, plen);
	}
	return fl;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
	struct nfqnl_msg_packet_hdr *ph;
	u_int32_t id = 0;

	ph = nfq_get_msg_packet_hdr(nfa);
	if(ph)id = ntohl(ph->packet_id);

	unsigned char *pdata; unsigned int plen;
	plen = nfq_get_payload(nfa, &pdata);

	puts(quenum?"Outbound callback":"Inbound callback");

	int changed;
	if(quenum)changed = changePacket(pdata, plen, "gzip,", "     ", 5);
	else changed = changePacket(pdata, plen, "Michael", "GILBERT", 7);

	printf("payload len = %d, data = ", plen);
	for(unsigned int i=0; i<plen; i++)printf("%02X ", pdata[i]);
	puts("");

	if(changed)return nfq_set_verdict(qh, id, quenum?NF_ACCEPT:NF_REPEAT, plen, pdata);
	puts("Success!");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

struct PktSession {
private:
	struct nfq_handle *hdl;
	struct nfq_q_handle *quehdl;
	int errCode;

public:
	PktSession(const u_int16_t queue_num, nfq_callback* callback){
		hdl = nfq_open();
		if(!hdl){errCode = 1; return;} // cannot open library handle
		if(nfq_unbind_pf(hdl, AF_INET) < 0){errCode = 2; return;} // cannot unbind existing nf_queue handler
		if(nfq_bind_pf(hdl, AF_INET) < 0){errCode = 3; return;} // cannot bind new nf_queue handler

		quehdl = nfq_create_queue(hdl, queue_num, callback, NULL);
		if(!quehdl){errCode = 4; return;} // cannot open netfilter queue
		if(nfq_set_mode(quehdl, NFQNL_COPY_PACKET, 0xffff) < 0){errCode = 5; return;} // cannot set mode
		errCode = 0;
	}
	~PktSession(){
		nfq_destroy_queue(quehdl);
		nfq_unbind_pf(hdl, AF_INET);
		nfq_close(hdl);
	}
	int get_error_code(){return errCode;}
	int recieve_packet(unsigned char *buf, unsigned size){
		int fd = nfq_fd(hdl), rv;
		if((rv = recv(fd, buf, size, 0)) >= 0){
			nfq_handle_packet(hdl, (char*)buf, rv);
			return 0; // recieved packet
		}
		if(errno == ENOBUFS)return 1; // losing packet
		return -1; // recieving fail
	}
};

int main(int argc, char **argv){
	if(argc < 2){
		puts("Usage : sudo ./modifyweb #(0 or 1)");
		return 0;
	}
	if(sscanf(argv[1], "%d", &quenum) != 1){
		puts("Usage : sudo ./modifyweb #(0 or 1)");
		return 0;
	}
	printf("%d\n", quenum);

	PktSession pktssn(quenum, &cb); // server -> client

	if(pktssn.get_error_code() > 0){
		puts("Failed to Connect the Queue");
		return pktssn.get_error_code();
	}

	unsigned char buf[4096] __attribute__ ((aligned));

	while(1){
		int val = pktssn.recieve_packet(buf, sizeof(buf));
		if(val < 0)break;
	}
	return 0;
}
