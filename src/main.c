#include <pcap.h>
#include <protocol.h>
#include "driver.h"
int main()
{
    pcap_t *pcap;
    pcap = open_device("wlp1s0");
    net_packet *r_packet = (net_packet *)malloc(sizeof(net_packet));
    r_packet->data = malloc(1516);
    ether_packet *e_pack = (ether_packet *)malloc(sizeof(ether_packet));

    while (1)
    {
        read_packet(pcap, r_packet);
        printf("Detect a %d bit pack\n", r_packet->size);
        e_pack = (ether_packet *)r_packet->data;
        switch (ntohs(e_pack->protocol))
        {
        case PROTOCOL_ARP:
            /* code */
            printf("Protocol ARP found\n");
            break;
        case PROTOCOL_IP:
            printf("Protocol IP found\n");
            break;
        default:
            break;
        }
    }
    return 0;
}