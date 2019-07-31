#pragma once
#include <stdint.h>

#define ETHERTYPE_IP 0x0800       /* IP */
#define ETHERTYPE_ARP 0x0806      /* Address resolution */
#define ETHERTYPE_REVARP 0x8035   /* Reverse ARP */
#define ETHERTYPE_AT 0x809B       /* AppleTalk protocol */
#define ETHERTYPE_IPV6 0x86dd     /* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK 0x9000 /* used to test interfaces */

///////////////////////////

struct __attribute__((aligned(1), packed)) mac_addr
{
    uint8_t oui[3];
    uint8_t nic[3];
};

struct eth_header
{
    mac_addr dest; /* destination eth addr	*/
    mac_addr src;  /* source ether addr	*/
    uint16_t type; /* packet type ID field	*/
};
