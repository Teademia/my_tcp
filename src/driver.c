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
                          0,             // 读取超时（以毫秒为单位）
                          err_buf);
    return pcap;
}

net_packet *read_packet(pcap_t *pcap)
{

    net_packet *packet = alloc_packet_for_read();

    struct pcap_pkthdr *pkthdr;
    const uint8_t *pkt_data = &a;
    pcap_next_ex(pcap, &pkthdr, &pkt_data);
    memcpy(packet->data, pkt_data, pkthdr->len);
    packet->size = pkthdr->len;
    return packet;
}
net_packet *alloc_packet_for_read()
{
    net_packet *packet = (net_packet *)malloc(sizeof(net_packet));
    packet->data = packet->payload;
    packet->size = 0;
    return packet;
}