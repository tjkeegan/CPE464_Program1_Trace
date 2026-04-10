#include "trace.h"

int main(int argc, char *argv[]) {
    // parse command line arguments
    if (argc == 4) {
        // check > value
        if (argv[3][0] != '>') {
            perror("acceptable format:\n\ttrace 'tracefile.pcap'\n\ttrace 'tracefile.pcap' > 'outputfile.txt'");
            exit(1);
        }
    }
    else if (argc != 2) {
        perror("acceptable format:\n\ttrace 'tracefile.pcap'\n\ttrace 'tracefile.pcap' > 'outputfile.txt'");
        exit(1);
    }

    // open .pcap file using pcap_open_offline()
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        perror("error opening .pcap file"); // update to print error message from errbuf
        exit(1);
    }

    // iterate over packets using pcap_next_ex()
    struct pcap_pkthdr *header;
    const unsigned char *data;
    int packet_count = 0;
    int pcap_ret = pcap_next_ex(handle, &header, &data);
    while (pcap_ret == 1) {
        printf("\nPacket number: %d  Packet Len: %d\n", ++packet_count, header->caplen);
        ethernet(data);
        pcap_ret = pcap_next_ex(handle, &header, &data);
    }
    if (pcap_ret != PCAP_ERROR_BREAK) {
        perror("error reading .pcap file");
        exit(1);
    }
        
    // close .pcap file using pcap_close()
    pcap_close(handle);
    return 0;
}

void ethernet(const unsigned char *data) {
    // parse dest MAC, src MAC, type
    uint8_t dest_mac[MAC_LENGTH];
    uint8_t src_mac[MAC_LENGTH];
    uint16_t type; // 2 bytes for type

    char dest_mac_str[MAC_STR_LENGTH];
    char src_mac_str[MAC_STR_LENGTH];
    char type_str[8]; // enough to hold "Unknown" + null terminator

    memcpy(dest_mac, data, MAC_LENGTH);
    memcpy(src_mac, data + MAC_LENGTH, MAC_LENGTH);   
    memcpy(&type, data + 2 * MAC_LENGTH, 2);
    type = ntohs(type); // convert from network byte order to host byte order

    ether_ntoa_r((struct ether_addr *)dest_mac, dest_mac_str);
    ether_ntoa_r((struct ether_addr *)src_mac, src_mac_str);
    if (type == ARP_TYPE) {
        memcpy(type_str, "ARP", 4);
    }
    else if (type == IPV4_TYPE) {
        memcpy(type_str, "IP", 3);
    }
    else {
        memcpy(type_str, "Unknown", 8);
    }

    // print info
    printf(
        "\n\tEthernet Header\n"
        "\t\tDest MAC: %s\n"
        "\t\tSource MAC: %s\n"
        "\t\tType: %s\n",
        dest_mac_str, src_mac_str, type_str
    );

    // parse next header based on type
    if (type == ARP_TYPE) {
        arp(data + ETHERNET_HEADER_LENGTH);
    }
    else if (type == IPV4_TYPE) {
        // parse IPv4 header
        ip(data + ETHERNET_HEADER_LENGTH);
    }
    // skip unknown packet types
}

void arp(const unsigned char *data) {
    // parse opcode, sender MAC, sender IP, targer MAC, target IP
    uint16_t opcode; // 2 bytes for opcode
    uint8_t sender_mac[MAC_LENGTH];
    uint8_t sender_ip[IP_LENGTH];
    uint8_t target_mac[MAC_LENGTH];
    uint8_t target_ip[IP_LENGTH];

    char opcode_str[8]; // enough to hold "Unknown" + null terminator
    char sender_mac_str[MAC_STR_LENGTH];
    char sender_ip_str[IP_STR_LENGTH];
    char target_mac_str[MAC_STR_LENGTH];
    char target_ip_str[IP_STR_LENGTH];

    memcpy(&opcode, data + OPCODE_OFFSET, 2);
    opcode = ntohs(opcode); // convert from network byte order to host byte order
    memcpy(sender_mac, data + SENDER_OFFSET, MAC_LENGTH);
    memcpy(sender_ip, data + SENDER_OFFSET + MAC_LENGTH, IP_LENGTH);
    memcpy(target_mac, data + TARGET_OFFSET, MAC_LENGTH);
    memcpy(target_ip, data + TARGET_OFFSET + MAC_LENGTH, IP_LENGTH);

    if (opcode == 1) {
        memcpy(opcode_str, "Request", 8);
    }
    else if (opcode == 2) {
        memcpy(opcode_str, "Reply", 6);
    }
    else {
        memcpy(opcode_str, "Unknown", 8);
    }
    
    ether_ntoa_r((struct ether_addr *)sender_mac, sender_mac_str);
    inet_ntop(AF_INET, sender_ip, sender_ip_str, IP_STR_LENGTH);
    ether_ntoa_r((struct ether_addr *)target_mac, target_mac_str);
    inet_ntop(AF_INET, target_ip, target_ip_str, IP_STR_LENGTH);

    // print info
    printf(
        "\n\tARP header\n"
        "\t\tOpcode: %s\n"
        "\t\tSender MAC: %s\n"
        "\t\tSender IP: %s\n"
        "\t\tTarget MAC: %s\n"
        "\t\tTarget IP: %s\n\n",
        opcode_str, sender_mac_str, sender_ip_str, target_mac_str, target_ip_str
    );
}

void ip(const unsigned char *data) {
    // parse IPv4 header
    uint16_t total_len; // 2 bytes for total length
    uint8_t version_ihl; // 1 byte for version and IHL
    uint8_t header_len; // for storing calculated header size
    uint8_t ttl; // 1 byte for TTL
    uint8_t protocol; // 1 byte for protocol
    uint16_t cksum; // 2 bytes for checksum
    uint8_t sender_ip[IP_LENGTH];
    uint8_t dest_ip[IP_LENGTH];

    char protocol_str[8]; // enough to hold "Unknown" + null terminator
    char cksum_str[10]; // enough to hold "Incorrect" + null terminator
    char sender_ip_str[IP_STR_LENGTH];
    char dest_ip_str[IP_STR_LENGTH];

    memcpy(&total_len, data + 2, 2);
    total_len = ntohs(total_len);
    memcpy(&version_ihl, data, 1);
    header_len = (version_ihl & 0x0f) * 4;
    memcpy(&ttl, data + 8, 1);
    memcpy(&protocol, data + 9, 1);
    memcpy(&cksum, data + 10, 2);
    cksum = ntohs(cksum);
    memcpy(sender_ip, data + 12, IP_LENGTH);
    memcpy(dest_ip, data + 16, IP_LENGTH);

    if (protocol == 1) {
        memcpy(protocol_str, "ICMP", 5);
    }
    else if (protocol == 6) {
        memcpy(protocol_str, "TCP", 4);
    }
    else if (protocol == 17) {
        memcpy(protocol_str, "UDP", 4);
    }
    else {
        memcpy(protocol_str, "Unknown", 8);
    }

    if (in_cksum((unsigned short *)data, header_len) == 0) {
        memcpy(cksum_str, "Correct", 8);
    } else {
        memcpy(cksum_str, "Incorrect", 10);
    }
 
    inet_ntop(AF_INET, sender_ip, sender_ip_str, IP_STR_LENGTH);
    inet_ntop(AF_INET, dest_ip, dest_ip_str, IP_STR_LENGTH);

    // print info
    printf(
        "\n\tIP Header\n"
        "\t\tIP PDU Len: %d\n"
        "\t\tHeader Len (bytes): %d\n"
        "\t\tTTL: %d\n"
        "\t\tProtocol: %s\n"
        "\t\tChecksum: %s (0x%04x)\n"
        "\t\tSender IP: %s\n"
        "\t\tDest IP: %s\n\n",
        total_len, header_len, ttl, protocol_str, cksum_str, cksum, sender_ip_str, dest_ip_str
    );
}