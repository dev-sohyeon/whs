#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ethheader* eth = (struct ethheader*)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

            printf("Source MAC: ");
            for (int i = 0; i < 6; ++i) {
                printf("%02X", eth->ether_shost[i]);
                if (i < 5) printf(":");
            }
            printf("\n");

            printf("Destination MAC: ");
            for (int i = 0; i < 6; ++i) {
                printf("%02X", eth->ether_dhost[i]);
                if (i < 5) printf(":");
            }
            printf("\n");

            printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
            printf("Source Port: %u\n", ntohs(tcp->tcp_sport));
            printf("Destination Port: %u\n", ntohs(tcp->tcp_dport));

            int tcp_data_offset = TH_OFF(tcp) * 4;
            int data_len = ntohs(ip->iph_len) - ip->iph_ihl * 4 - tcp_data_offset;

            printf("Message: ");
            for (int i = 0; i < data_len && i < 20; ++i) {
                printf("%c", packet[sizeof(struct ethheader) + ip->iph_ihl * 4 + tcp_data_offset + i]);
            }
            if (data_len > 20) printf("...");
            printf("\n\n");
        }
    }
}

int main() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); 
    return 0;
}