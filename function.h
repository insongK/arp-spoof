#include "pch.h"
#include "headers.h"

void print_err_command();
void get_network_info(const char *iface, char *my_ipv4, uint8_t my_mac[6]);
void send_arp_packet(pcap_t* pcap, uint8_t eth_dmac[6], uint8_t eth_smac[6], uint16_t arp_op,
                     uint8_t arp_smac[6],    char* sip, uint8_t arp_tmac[6], char* tip);
void resolve_mac_addr(pcap_t* pcap, char* my_ipv4, char* sender_ip, uint8_t* resolved_mac);
void* infect_arp_table(void* arg);
void* relay_packets(void* arg);
