#ifndef HEADERS_H
#define HEADERS_H

#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_IPV4 0x0800

#define ARP_HTYPE_ETHER 1
#define ARP_OPER_RQUEST 1
#define ARP_OPER_REPLY 2

#define MAC_ADDR_SIZE 6
#define IPV4_ADDR_SIZE 4

struct ethernet_header
{
    u_int8_t  dst_mac[MAC_ADDR_SIZE];
    u_int8_t  src_mac[MAC_ADDR_SIZE];
    u_int16_t ether_type;
};

struct ipv4_header
{
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    struct in_addr src_ip;
    struct in_addr dst_ip;
};

struct tcp_header
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

#pragma pack(push, 1)
struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[MAC_ADDR_SIZE];
    uint32_t spa;
    uint8_t tha[MAC_ADDR_SIZE];
    uint32_t tpa;
};
#pragma pack(pop)

struct ArpInfectArgs {
    pcap_t* pcap;
    uint8_t attacker_mac[6];

    char* sender_ip;
    uint8_t sender_mac[6];

    char* target_ip;
    uint8_t target_mac[6];
};
#endif
