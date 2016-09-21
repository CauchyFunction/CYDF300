// pcaplib.h
#pragma once

void opendevice(unsigned int bytes, unsigned int pktcnt);
void closedevice(pcap_t* pd);
