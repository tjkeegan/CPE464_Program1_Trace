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

    char protocol_str[strlen("Unknown") + 1];
    char cksum_str[strlen("Incorrect") + 1];
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

    if (protocol == ICMP_TYPE) {
        memcpy(protocol_str, "ICMP", strlen("ICMP") + 1);
    }
    else if (protocol == TCP_TYPE) {
        memcpy(protocol_str, "TCP", strlen("TCP") + 1);
        
        char pseudo_hdr[total_len];
        memcpy(pseudo_hdr, sender_ip, IP_LENGTH);
        memcpy(pseudo_hdr + IP_LENGTH, dest_ip, IP_LENGTH);
        pseudo_hdr[8] = 0;
        pseudo_hdr[9] = protocol;
        pseudo_hdr[10] = htons(total_len - header_len); 
        memcpy(pseudo_hdr + 10, data + header_len, total_len - header_len);
    }
    else if (protocol == UDP_TYPE) {
        memcpy(protocol_str, "UDP", strlen("UDP") + 1);
    }
    else {
        memcpy(protocol_str, "Unknown", strlen("Unknown") + 1);
    }

    if (in_cksum((unsigned short *)data, header_len) == 0) {
        memcpy(cksum_str, "Correct", strlen("Correct") + 1);
    } else {
        memcpy(cksum_str, "Incorrect", strlen("Incorrect") + 1);
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

    if (protocol == ICMP_TYPE) {
        //icmp(data + header_len);
    }
    else if (protocol == TCP_TYPE) {
        memcpy(data + header_len - 12, pseudo_hdr, 12);
        tcp(data + header_len - 12);
    }
    else if (protocol == UDP_TYPE) {
        //udp(data + header_len);
    }
}

void tcp(const unsigned char *data) {
    // parse TCP header
    uint16_t seg_len;
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flags;
    uint16_t win_size;
    uint16_t cksum;

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

    flags & 0x2 ? memcpy(syn_flag_str, "Yes", strlen("Yes") + 1) : memcpy(syn_flag_str, "No", strlen("No") + 1);
    flags & 0x4 ? memcpy(rst_flag_str, "Yes", strlen("Yes") + 1) : memcpy(rst_flag_str, "No", strlen("No") + 1);
    flags & 0x1 ? memcpy(fin_flag_str, "Yes", strlen("Yes") + 1) : memcpy(fin_flag_str, "No", strlen("No") + 1);
    flags & 0x10 ? memcpy(ack_flag_str, "Yes", strlen("Yes") + 1) : memcpy(ack_flag_str, "No", strlen("No") + 1);

    if (in_cksum((unsigned short *)data, seg_len) == 0) {
        memcpy(cksum_str, "Correct", strlen("Correct") + 1);
    } else {
        memcpy(cksum_str, "Incorrect", strlen("Incorrect") + 1);
    }

    printf(
        "\n\tTCP Header\n"
        "\t\tSegment Len (bytes): %d\n"
        "\t\tSource Port: %d\n"
        "\t\tDest Port: %d\n"
        "\t\tSequence Number: %u\n"
        "\t\tACK Number: %u\n"
        "\t\tSYN Flag: %s\n"
        "\t\tRST Flag: %s\n"
        "\t\tFIN Flag: %s\n"
        "\t\tACK Flag: %s\n"
        "\t\tWindow Size: %d\n"
        "\t\tChecksum: %s (0x%04x)\n\n",
        seg_len, src_port, dest_port, seq_num, ack_num, syn_flag_str, rst_flag_str, fin_flag_str, ack_flag_str, win_size, cksum_str, cksum
    );
}