// pcaplib.h
#pragma once

void getdevice(char* device);
void opendevice(char* device, unsigned int bytes, unsigned int pktcnt);
void closedevice(pcap_t* pd);
