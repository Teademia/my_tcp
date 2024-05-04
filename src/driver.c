#include "driver.h"

static uint8_t a = 1;
pcap_t *open_device(const char *net_card_name)
{
    pcap_t *pcap;
    char err_buf[PCAP_ERRBUF_SIZE];
    printf("Going to open %s\n", net_card_name);
    pcap = pcap_open_live(net_card_name, // 设置字符串
                          65536,         // 要捕获的最大字节数
                          1,             // 混杂模式
                          1000,          // 读取超时（以毫秒为单位）
                          err_buf);
    return pcap;
}

int read_packet(pcap_t *pcap, net_packet *net_packet_ptr)
{
    struct pcap_pkthdr *pkthdr;
    const uint8_t *pkt_data = &a;
    pcap_next_ex(pcap, &pkthdr, &pkt_data);
    memcpy(net_packet_ptr->data, pkt_data, pkthdr->len);
    net_packet_ptr->size = pkthdr->len;
    return pkthdr->len;
}
net_packet *alloc_packet_for_read()
{
    net_packet *packet = (net_packet *)malloc(sizeof(net_packet));
    packet->data = packet->payload;
    packet->size = 0;
    return packet;
}