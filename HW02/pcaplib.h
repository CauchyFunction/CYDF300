// pcaplib.h
#pragma once

int getGatewayIP(int* ip);
void sendFakePacket(int* vct, int* gtw);

void closedevice(pcap_t* pd);
