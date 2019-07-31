#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include "../header/protocol/all.h"

#define MAX_MTU 1500
void printMACAddress(mac_addr mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}

void printIPAddress(ip_addr ipAddr)
{
    printf("%d.%d.%d.%d", ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}

void printTCPPort(uint16_t port)
{
    printf("%d", port);
}

void _printPacket(const unsigned char *p, uint32_t size)
{
    int len = 0;
    while (len < size)
    {
        printf("%02X ", *(p++));
        if (!(++len % 16))
        {
            printf("\n");
        }
    }
    if (size % 16)
    {
        printf("\n");
    }
}

bool arpSend(pcap_t *handle, mac_addr srcMAC, mac_addr destMAC, uint16_t arpOpcode, ip_addr arpSrcIP, mac_addr arpSrcMAC, ip_addr arpDestIP, mac_addr arpDestMAC)
{
    uint8_t buffer[MAX_MTU];
    int packetIndex = 0;

    eth_header eth;
    eth.type = htons(ETHERTYPE_ARP);
    eth.src = srcMAC;
    eth.dest = destMAC;
    memcpy(buffer, &eth, sizeof(eth_header));
    packetIndex += sizeof(eth_header);
    arp_header arp;

    arp.hardware_type = htons(ARPHRD_ETHER);
    arp.protocol_type = htons(ARPPRO_IPV4);
    arp.hardware_size = MAC_LENGTH;
    arp.protocol_size = IPV4_LENGTH;
    arp.opcode =  htons(arpOpcode);
    arp.sender_mac = arpSrcMAC;
    arp.sender_ip = arpSrcIP;
    arp.target_mac = arpDestMAC;
    arp.target_ip = arpDestIP;

    memcpy(buffer+packetIndex, &arp, sizeof(arp_header));
    packetIndex += sizeof(arp_header);

    if (pcap_sendpacket(handle, buffer, packetIndex) != 0)
    {
        return false;
    }
    return true;
}

bool arpRequest(pcap_t *handle, ip_addr srcIP, mac_addr srcMAC, ip_addr destIP) {
    mac_addr broadcastMAC;
    memset(&broadcastMAC, 0xff, sizeof(mac_addr));
    mac_addr responseMAC;
    memset(&responseMAC, 0, sizeof(mac_addr));
    return arpSend(handle, srcMAC, broadcastMAC, ARPOP_REQUEST, srcIP, srcMAC, destIP, responseMAC);
}

bool arpReply(pcap_t *handle, ip_addr srcIP, mac_addr srcMAC, ip_addr destIP, mac_addr destMAC) {
    return arpSend(handle, srcMAC, destMAC, ARPOP_REPLY, srcIP, srcMAC, destIP, destMAC);
}

bool arpReverseRequest(pcap_t *handle, mac_addr srcMAC) {
    mac_addr broadcastMAC;
    memset(&broadcastMAC, 0xff, sizeof(mac_addr));
    mac_addr responseMAC;
    memset(&responseMAC, 0, sizeof(mac_addr));
    ip_addr responseIP;
    memset(&responseIP, 0, sizeof(ip_addr));
    return arpSend(handle, srcMAC, broadcastMAC, ARPOP_RREQUEST, responseIP, srcMAC, responseIP, srcMAC);
}


void printPacket(const unsigned char *p, const struct pcap_pkthdr *h)
{
    _printPacket(p, h->len);
}
void printPacket(const unsigned char *p, uint32_t size)
{
    _printPacket(p, size);
}

bool equalIPAddr(ip_addr x, ip_addr y)
{
    //return memcmp(&x, &y, sizeof(ip_addr))==0;
    return x.a == y.a && x.b == y.b && x.c == y.c && x.d == y.d;
}
bool equalMACAddr(mac_addr x, mac_addr y)
{
    return x.nic[0] == y.nic[0] && x.nic[1] == y.nic[1] && x.nic[2] == y.nic[2] && x.oui[0] == y.oui[0] && x.oui[1] == y.oui[1] && x.oui[2] == y.oui[2];
}
bool getTargetIPGetMACAddress(pcap_t *handle, ip_addr myIPAddr, mac_addr myMACAddr, ip_addr target, mac_addr *out)
{
    while (true)
    {
        if(!arpRequest(handle, myIPAddr, myMACAddr, target)) {
            continue;
        }

        struct pcap_pkthdr *header;
        const u_char *packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        int packetIndex = 0;
        eth_header *eth = (eth_header *)packet;
        packetIndex += sizeof(eth_header);
        if (ntohs(eth->type) == ETHERTYPE_ARP)
        {
            arp_header *arp = (arp_header *)(packet + packetIndex);
            packetIndex += sizeof(arp_header);
            if (arp->opcode == htons(ARPOP_REPLY) && equalIPAddr(arp->sender_ip, target) && equalIPAddr(arp->target_ip, myIPAddr) && equalMACAddr(arp->target_mac, myMACAddr))
            {
                //printMACAddress(arp->sender_mac);
                *out = (arp->sender_mac);
                //printf("\n");
                //printMACAddress(*out);
                return true;
            }
        }
    }
    return true;
}
