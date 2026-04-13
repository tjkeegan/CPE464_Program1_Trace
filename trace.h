#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "checksum.h"

// ETHERNET HEADER
#define MAC_LENGTH 6 // length in bytes: ff:ff:ff:ff:ff:ff
#define MAC_STR_LENGTH 18 // length in chars: ff:ff:ff:ff:ff:ff + \0
#define ETHERNET_TYPE_LENGTH 2 // length in bytes
#define ETHERNET_TYPE_STR_LENGTH 8 // in chars: "Unknown" + \0
#define IP_LENGTH 4 // length in bytes: 111.111.111.111
#define IP_STR_LENGTH 16 // length in chars: 111.111.111.111 + \0
#define ARP_TYPE 0x0806
#define IPV4_TYPE 0x0800
#define ETHERNET_HEADER_LENGTH (2 * MAC_LENGTH + ETHERNET_TYPE_LENGTH)

// ARP HEADER
#define OPCODE_LENGTH 2 // length in bytes
#define OPCODE_STR_LENGTH 8 // length in chars: "Unknown" + \0
#define OPCODE_OFFSET 6
#define SENDER_OFFSET (OPCODE_OFFSET + 2)
#define TARGET_OFFSET (SENDER_OFFSET + MAC_LENGTH + IP_LENGTH)

// IP HEADER
#define TOTAL_LEN_LENGTH 2 // length in bytes
#define VERSION_IHL_LENGTH 1 // length in bytes
#define TTL_LENGTH 1 // length in bytes
#define PROTOCOL_LENGTH 1 // length in bytes
#define PROTOCOL_STR_LENGTH 8 // length in chars: "Unknown" + \0
#define CHECKSUM_LENGTH 2 // length in bytes
#define CHECKSUM_STR_LENGTH 10 // length in chars: "Incorrect" + \0
#define ICMP_TYPE 1
#define TCP_TYPE 6
#define UDP_TYPE 17
#define PSEUDO_HDR_LENGTH 12

void ethernet(const unsigned char *data);
void arp(const unsigned char *data);

void ip(const unsigned char *data);
void ip_protocol_format(uint8_t protocol, char *protocol_str);
void ip_checksum(unsigned char *data, uint8_t header_len, char *cksum_str);
void ip_print(uint16_t total_len, uint8_t header_len, uint8_t ttl, char *protocol_str, char *cksum_str, uint16_t cksum, char *sender_ip_str, char *dest_ip_str);
void ip_next_header(const unsigned char *data, uint16_t total_len, uint8_t header_len, uint8_t protocol, uint8_t *sender_ip, uint8_t *dest_ip);

void tcp(unsigned char *data);
void tcp_port_format(uint16_t port, char *port_str, size_t len);
void tcp_flags(uint8_t flags, char *syn_flag_str, char *rst_flag_str, char *fin_flag_str, char *ack_flag_str);
void tcp_checksum(unsigned char *data, uint16_t seg_len, char *cksum_str);
void tcp_print(uint16_t seg_len, char *src_port_str, char *dest_port_str, uint32_t seq_num, uint32_t ack_num, char *syn_flag_str, char *rst_flag_str, char *fin_flag_str, char *ack_flag_str, uint16_t win_size, char *cksum_str, uint16_t cksum);

void icmp(const unsigned char *data);
void udp(const unsigned char *data);