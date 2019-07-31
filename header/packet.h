#pragma once
#include <stdint.h>
#include <pcap/pcap.h>
#include "protocol/all.h"

void printMACAddress(mac_addr);
void printIPAddress(ip_addr);
void printTCPPort(uint16_t);

void packetParse(eth_header*, const u_char *, int *);

void printPacket(const unsigned char *, const struct pcap_pkthdr *);
void printPacket(const unsigned char *, uint32_t);

void _printPacket(const unsigned char *, uint32_t);

bool arpSend(pcap_t *handle, mac_addr srcMAC, mac_addr destMAC, uint16_t arpOpcode, ip_addr arpSrcIP, mac_addr arpSrcMAC, ip_addr arpDestIP, mac_addr arpDestMAC);
bool arpRequest(pcap_t *, ip_addr, mac_addr, ip_addr);
bool arpReply(pcap_t *, ip_addr, mac_addr, ip_addr, mac_addr);
bool arpReverseRequest(pcap_t *, mac_addr);

bool equalIPAddr(ip_addr, ip_addr);
bool equalMACAddr(mac_addr, mac_addr);
bool getTargetIPGetMACAddress(pcap_t *, ip_addr, mac_addr, ip_addr, mac_addr *);