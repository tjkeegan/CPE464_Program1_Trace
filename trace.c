#include "trace.h"

int main(int argc, char *argv[]) {
    // check command line arguments
    if (argc == 4) {
        // check > value
        if (argv[3][0] != '>') {
            printf("acceptable format:\n\ttrace 'tracefile.pcap'\n\ttrace 'tracefile.pcap' > 'outputfile.txt'\n");
            exit(1);
        }
    }
    else if (argc != 2) {
        printf("acceptable format:\n\ttrace 'tracefile.pcap'\n\ttrace 'tracefile.pcap' > 'outputfile.txt'\n");
        exit(1);
    }

    // open .pcap file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        perror("error opening .pcap file"); // update to print error message from errbuf
        exit(1);
    }

    // iterate over packets
    struct pcap_pkthdr *header;
    const unsigned char *data;
    int packet_count = 0;
    int pcap_ret = pcap_next_ex(handle, &header, &data);
    while (pcap_ret == 1) {
        printf("\nPacket number: %d  Packet Len: %d\n", ++packet_count, header->caplen);
        ethernet(data);
        pcap_ret = pcap_next_ex(handle, &header, &data);
    }

    // check for error in pcap_next_ex() loop
    if (pcap_ret != PCAP_ERROR_BREAK) {
        perror("error reading .pcap file");
        exit(1);
    }
        
    // close .pcap file using pcap_close()
    pcap_close(handle);
    return 0;
}

void ethernet(const unsigned char *data) {
    // define variables for dest MAC, source MAC, and type
    uint8_t dest_mac[MAC_LENGTH];
    uint8_t src_mac[MAC_LENGTH];
    uint16_t type;

    char dest_mac_str[MAC_STR_LENGTH];
    char src_mac_str[MAC_STR_LENGTH];
    char type_str[ETHERNET_TYPE_STR_LENGTH];

    // parse dest MAC, source MAC, and type from Ethernet header
    memcpy(dest_mac, data, MAC_LENGTH);
    memcpy(src_mac, data + MAC_LENGTH, MAC_LENGTH);   
    memcpy(&type, data + 2 * MAC_LENGTH, ETHERNET_TYPE_LENGTH);
    type = ntohs(type); // network byte order -> host byte order

    // write to strings for printing
    ether_ntoa_r((struct ether_addr *)dest_mac, dest_mac_str);
    ether_ntoa_r((struct ether_addr *)src_mac, src_mac_str);

    if (type == ARP_TYPE) {
        memcpy(type_str, "ARP", sizeof("ARP"));
    }
    else if (type == IPV4_TYPE) {
        memcpy(type_str, "IP", sizeof("IP"));
    }
    else {
        memcpy(type_str, "Unknown", sizeof("Unknown"));
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
        ip(data + ETHERNET_HEADER_LENGTH);
    }
    // skip unknown packet types
}

void arp(const unsigned char *data) {
    // define variables for opcode, sender MAC, sender IP, target MAC, and target IP
    uint16_t opcode;
    uint8_t sender_mac[MAC_LENGTH];
    uint8_t sender_ip[IP_LENGTH];
    uint8_t target_mac[MAC_LENGTH];
    uint8_t target_ip[IP_LENGTH];

    char opcode_str[OPCODE_STR_LENGTH];
    char sender_mac_str[MAC_STR_LENGTH];
    char sender_ip_str[IP_STR_LENGTH];
    char target_mac_str[MAC_STR_LENGTH];
    char target_ip_str[IP_STR_LENGTH];

    // parse fields from ARP header
    memcpy(&opcode, data + OPCODE_OFFSET, OPCODE_LENGTH);
    opcode = ntohs(opcode); // network byte order -> host byte order
    memcpy(sender_mac, data + SENDER_OFFSET, MAC_LENGTH);
    memcpy(sender_ip, data + SENDER_OFFSET + MAC_LENGTH, IP_LENGTH);
    memcpy(target_mac, data + TARGET_OFFSET, MAC_LENGTH);
    memcpy(target_ip, data + TARGET_OFFSET + MAC_LENGTH, IP_LENGTH);

    // write to strings for printing
    if (opcode == 1) {
        memcpy(opcode_str, "Request", sizeof("Request"));
    }
    else if (opcode == 2) {
        memcpy(opcode_str, "Reply", sizeof("Reply"));
    }
    else {
        memcpy(opcode_str, "Unknown", sizeof("Unknown"));
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
        "\t\tTarget IP: %s\n",
        opcode_str, sender_mac_str, sender_ip_str, target_mac_str, target_ip_str
    );
}

void ip(const unsigned char *data) {
    // define variables for total length, version/IHL, header length, TTL, protocol, checksum, sender IP, and dest IP
    uint16_t total_len;
    uint8_t version_ihl;
    uint8_t header_len; // for storing calculated header size
    uint8_t ttl;
    uint8_t protocol; 
    uint16_t cksum;
    uint8_t sender_ip[IP_LENGTH];
    uint8_t dest_ip[IP_LENGTH];

    char protocol_str[PROTOCOL_STR_LENGTH];
    char cksum_str[CHECKSUM_STR_LENGTH];
    char sender_ip_str[IP_STR_LENGTH];
    char dest_ip_str[IP_STR_LENGTH];

    // parse fields from IP header
    memcpy(&total_len, data + 2, TOTAL_LEN_LENGTH);
    total_len = ntohs(total_len);
    memcpy(&version_ihl, data, VERSION_IHL_LENGTH);
    header_len = (version_ihl & 0x0f) * 4; // mask version_ihl to get IHL, then multiply by 4 to get header length in bytes
    memcpy(&ttl, data + 8, TTL_LENGTH);
    memcpy(&protocol, data + 9, PROTOCOL_LENGTH);
    memcpy(&cksum, data + 10, CHECKSUM_LENGTH);
    cksum = ntohs(cksum);
    memcpy(sender_ip, data + 12, IP_LENGTH);
    memcpy(dest_ip, data + 16, IP_LENGTH);

    // write to strings for printing
    ip_protocol_format(protocol, protocol_str);
    ip_checksum((unsigned char *)data, header_len, cksum_str);
    inet_ntop(AF_INET, sender_ip, sender_ip_str, IP_STR_LENGTH);
    inet_ntop(AF_INET, dest_ip, dest_ip_str, IP_STR_LENGTH);

    // print info
    ip_print(total_len, header_len, ttl, protocol_str, cksum_str, cksum, sender_ip_str, dest_ip_str);

    // parse next header based on protocol
    ip_next_header(data, total_len, header_len, protocol, sender_ip, dest_ip);
}

void ip_protocol_format(uint8_t protocol, char *protocol_str) {
    if (protocol == ICMP_TYPE) {
        memcpy(protocol_str, "ICMP", sizeof("ICMP"));
    }
    else if (protocol == TCP_TYPE) {
        memcpy(protocol_str, "TCP", sizeof("TCP"));
    }
    else if (protocol == UDP_TYPE) {
        memcpy(protocol_str, "UDP", sizeof("UDP"));
    }
    else {
        memcpy(protocol_str, "Unknown", sizeof("Unknown"));
    }
}

void ip_checksum(unsigned char *data, uint8_t header_len, char *cksum_str) {
    if (in_cksum((unsigned short *)data, header_len) == 0) {
        memcpy(cksum_str, "Correct", sizeof("Correct"));
    } else {
        memcpy(cksum_str, "Incorrect", sizeof("Incorrect"));
    }
}

void ip_print(uint16_t total_len, uint8_t header_len, uint8_t ttl, char *protocol_str, char *cksum_str, uint16_t cksum, char *sender_ip_str, char *dest_ip_str) {
    printf(
        "\n\tIP Header\n"
        "\t\tIP PDU Len: %d\n"
        "\t\tHeader Len (bytes): %d\n"
        "\t\tTTL: %d\n"
        "\t\tProtocol: %s\n"
        "\t\tChecksum: %s (0x%04x)\n"
        "\t\tSender IP: %s\n"
        "\t\tDest IP: %s\n",
        total_len, header_len, ttl, protocol_str, cksum_str, cksum, sender_ip_str, dest_ip_str
    );
}

void ip_next_header(const unsigned char *data, uint16_t total_len, uint8_t header_len, uint8_t protocol, uint8_t *sender_ip, uint8_t *dest_ip) {
    if (protocol == ICMP_TYPE) {
        icmp(data + header_len);
    }
    else if (protocol == TCP_TYPE) {
        uint16_t tcp_len = total_len - header_len;
        unsigned char pseudo_hdr[PSEUDO_HDR_LENGTH + tcp_len];
        tcp_len = htons(tcp_len); // convert from host byte order to network byte order
        memcpy(pseudo_hdr, sender_ip, IP_LENGTH);
        memcpy(pseudo_hdr + IP_LENGTH, dest_ip, IP_LENGTH);
        pseudo_hdr[8] = 0;
        pseudo_hdr[9] = protocol;
        memcpy(pseudo_hdr + 10, &tcp_len, sizeof(uint16_t));
        memcpy(pseudo_hdr + 12, data + header_len, total_len - header_len);

        tcp(pseudo_hdr);
    }
    else if (protocol == UDP_TYPE) {
        udp(data + header_len);
    }
}

void tcp(unsigned char *data) {
    // parse TCP header
    uint16_t seg_len;
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flags;
    uint16_t win_size;
    uint16_t cksum;

    char src_port_str[16];
    char dest_port_str[16];
    char syn_flag_str[strlen("Yes") + 1];
    char rst_flag_str[strlen("Yes") + 1];
    char fin_flag_str[strlen("Yes") + 1];
    char ack_flag_str[strlen("Yes") + 1];
    char cksum_str[strlen("Incorrect") + 1];

    memcpy(&seg_len, data + 10, sizeof(uint16_t));
    seg_len = ntohs(seg_len); 
    memcpy(&src_port, data + PSEUDO_HDR_LENGTH, sizeof(uint16_t));
    src_port = ntohs(src_port);
    memcpy(&dest_port, data + PSEUDO_HDR_LENGTH + 2, sizeof(uint16_t));
    dest_port = ntohs(dest_port);
    memcpy(&seq_num, data + PSEUDO_HDR_LENGTH + 4, sizeof(uint32_t));
    seq_num = ntohl(seq_num);
    memcpy(&ack_num, data + PSEUDO_HDR_LENGTH + 8, sizeof(uint32_t));
    ack_num = ntohl(ack_num);
    memcpy(&flags, data + PSEUDO_HDR_LENGTH + 13, sizeof(uint8_t));
    memcpy(&win_size, data + PSEUDO_HDR_LENGTH + 14, sizeof(uint16_t));
    win_size = ntohs(win_size);
    memcpy(&cksum, data + PSEUDO_HDR_LENGTH + 16, sizeof(uint16_t));
    cksum = ntohs(cksum);

    tcp_port_format(src_port, src_port_str, sizeof(src_port_str));
    tcp_port_format(dest_port, dest_port_str, sizeof(dest_port_str));
    tcp_flags(flags, syn_flag_str, rst_flag_str, fin_flag_str, ack_flag_str);
    tcp_checksum(data, seg_len, cksum_str);
    tcp_print(seg_len, src_port_str, dest_port_str, seq_num, ack_num, syn_flag_str, rst_flag_str, fin_flag_str, ack_flag_str, win_size, cksum_str, cksum);
}

void tcp_port_format(uint16_t port, char *port_str, size_t len) {
    if (port == 80) {
        memcpy(port_str, "HTTP", sizeof("HTTP"));
    }
    else if (port == 443) {
        memcpy(port_str, "HTTPS", sizeof("HTTPS"));
    }
    else {
        snprintf(port_str, len, "%u", port);
    }
}

void tcp_flags(uint8_t flags, char *syn_flag_str, char *rst_flag_str, char *fin_flag_str, char *ack_flag_str) {
    flags & 0x2 ? memcpy(syn_flag_str, "Yes", sizeof("Yes")) : memcpy(syn_flag_str, "No", sizeof("No"));
    flags & 0x4 ? memcpy(rst_flag_str, "Yes", sizeof("Yes")) : memcpy(rst_flag_str, "No", sizeof("No"));
    flags & 0x1 ? memcpy(fin_flag_str, "Yes", sizeof("Yes")) : memcpy(fin_flag_str, "No", sizeof("No"));
    flags & 0x10 ? memcpy(ack_flag_str, "Yes", sizeof("Yes")) : memcpy(ack_flag_str, "No", sizeof("No"));
}

void tcp_checksum(unsigned char *data, uint16_t seg_len, char *cksum_str) {
    if (in_cksum((unsigned short *)data, PSEUDO_HDR_LENGTH + seg_len) == 0) {
        memcpy(cksum_str, "Correct", sizeof("Correct"));
    } else {
        memcpy(cksum_str, "Incorrect", sizeof("Incorrect"));
    }
}

void tcp_print(uint16_t seg_len, char *src_port_str, char *dest_port_str, uint32_t seq_num, uint32_t ack_num, char *syn_flag_str, char *rst_flag_str, char *fin_flag_str, char *ack_flag_str, uint16_t win_size, char *cksum_str, uint16_t cksum) {
    printf(
        "\n\tTCP Header\n"
        "\t\tSegment Length: %d\n"
        "\t\tSource Port:  %s\n"
        "\t\tDest Port:  %s\n"
        "\t\tSequence Number: %u\n"
        "\t\tACK Number: %u\n"
        "\t\tSYN Flag: %s\n"
        "\t\tRST Flag: %s\n"
        "\t\tFIN Flag: %s\n"
        "\t\tACK Flag: %s\n"
        "\t\tWindow Size: %d\n"
        "\t\tChecksum: %s (0x%04x)\n",
        seg_len, src_port_str, dest_port_str, seq_num, ack_num, syn_flag_str, rst_flag_str, fin_flag_str, ack_flag_str, win_size, cksum_str, cksum
    );
}

void icmp(const unsigned char *data) {

    uint8_t type;

    char type_str[strlen("Request") + 1];

    memcpy(&type, data, 1);

    if (type == 0) {
        memcpy(type_str, "Reply", strlen("Reply") + 1);
    }
    else if (type == 8) {
        memcpy(type_str, "Request", strlen("Request") + 1);
    }
    else {
        snprintf(type_str, sizeof(type_str), "%u", type);
    }

    printf(
        "\n\tICMP Header\n"
        "\t\tType: %s\n",
        type_str
    );
}

void udp(const unsigned char *data) {

    uint16_t src_port;
    uint16_t dest_port;

    char src_port_str[6];
    char dest_port_str[6];
    
    memcpy(&src_port, data, sizeof(src_port));
    src_port = ntohs(src_port);
    memcpy(&dest_port, data + 2, sizeof(dest_port));
    dest_port = ntohs(dest_port);

    if (src_port == 53) {
        memcpy(src_port_str, "DNS", sizeof("DNS"));
    }
    else {
        snprintf(src_port_str, sizeof(src_port_str), "%u", src_port);
    }
    
    if (dest_port == 53) {
        memcpy(dest_port_str, "DNS", sizeof("DNS"));
    }
    else {
        snprintf(dest_port_str, sizeof(dest_port_str), "%u", dest_port);
    }

    printf(
        "\n\tUDP Header\n"
        "\t\tSource Port:  %s\n"
        "\t\tDest Port:  %s\n",
        src_port_str, dest_port_str
    );
}