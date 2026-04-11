#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "checksum.h"

#define MAC_LENGTH 6
#define MAC_STR_LENGTH 18
#define IP_LENGTH 4
#define IP_STR_LENGTH 16
#define ETHERNET_HEADER_LENGTH 14
#define OPCODE_OFFSET 6
#define SENDER_OFFSET (OPCODE_OFFSET + 2)
#define TARGET_OFFSET (SENDER_OFFSET + MAC_LENGTH + IP_LENGTH)
#define ARP_TYPE 0x0806
#define IPV4_TYPE 0x0800
#define ICMP_TYPE 1
#define TCP_TYPE 6
#define UDP_TYPE 17
#define PSEUDO_HDR_LENGTH 12

void ethernet(const unsigned char *data);
void arp(const unsigned char *data);
void ip(const unsigned char *data);
void tcp(unsigned char *data);