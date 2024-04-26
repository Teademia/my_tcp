#include <pcap.h>
#include <sys/types.h>
#include <netinet/ether.h> // for ether_ntoa
#include <netinet/in.h>    // for ntohs
#include <arpa/inet.h>     // for inet_ntoa
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <string.h>
#include "protocol.h"

#define PACKET_MAX_SIZE 1516 // 收发数据包的最大大小

#define IPV4_ADDR_SIZE 4 // IP地址长度
#define MAC_ADDR_SIZE 6  // MAC地址长度
#define min(a, b) ((a) < (b) ? (a) : (b))
typedef struct
{
    uint8_t dest_mac[6];   // Destination MAC address
    uint8_t source_mac[6]; // Source MAC address
    uint16_t ether_type;   // Type field
} my_ether_header;

typedef struct _xnet_packet_t
{
    uint16_t size;                    // 包中有效数据大小
    uint8_t *data;                    // 包的数据起始地址
    uint8_t payload[PACKET_MAX_SIZE]; // 最大负载数据量
} xnet_packet_t;

typedef union _xipaddr_t
{
    uint8_t array[IPV4_ADDR_SIZE]; // 以数据形式存储的ip
    uint32_t addr;                 // 32位的ip地址
} xipaddr_t;

typedef struct _xarp_entry_t
{
    xipaddr_t ipaddr;               // ip地址
    uint8_t macaddr[MAC_ADDR_SIZE]; // mac地址
    uint8_t state;                  // 状态位
    uint16_t tmo;                   // 当前超时
    uint8_t retry_cnt;              // 当前重试次数
} xarp_entry_t;

int main()
{
    pcap_t *pcap;
    char err_buf[PCAP_ERRBUF_SIZE];

    pcap = pcap_open_live("vmnet1", // 设置字符串
                          65536,    // 要捕获的最大字节数
                          1,        // 混杂模式
                          1000,     // 读取超时（以毫秒为单位）
                          err_buf);

    struct pcap_pkthdr *header;
    const __u_char *data;
    int err;

    xnet_packet_t packet;
    while ((err = pcap_next_ex(pcap, &header, &data)) >= 0)
    {
        if (err == 0)
            continue; // Timeout elapsed

        else
        {
            printf("Ethernet Frame Readed");
            packet.size = min(header->len, PACKET_MAX_SIZE);
            packet.data = data;

            // 解析以太网帧头部
            my_ether_header *eth_header = (my_ether_header *)packet.data;
            // printf("Ethernet Type: 0x%04X\n", ntohs(eth_header->ether_type));
            switch (ntohs(eth_header->ether_type))
            {
            case ETH_P_IP:
                printf("Find IP Protocol Pack\n");
                break;
            case ETH_P_ARP:
                printf("Find ARP Protocol Pack\n");
                break;
            case ETH_P_IPV6:
                printf("Find IPV6 Protocol Pack\n");
                break;
            default:
                printf("Unknown Protocol at 0x%04X\n", ntohs(eth_header->ether_type));
            }
        }
    }
    return 1;
}