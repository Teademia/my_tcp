#include <stdint.h>
#define PACKET_MAX_SIZE 1516
#define MAC_ADDR_SIZE 6
typedef struct _net_packet
{
    uint16_t size;                    // 包中有效数据大小
    uint8_t *data;                    // 包的数据起始地址
    uint8_t payload[PACKET_MAX_SIZE]; // 最大负载数据量
} net_packet;

typedef struct _ether_packet
{
    uint8_t dest[MAC_ADDR_SIZE]; // 目标mac地址
    uint8_t src[MAC_ADDR_SIZE];  // 源mac地址
    uint16_t protocol;           // 协议/长度
} ether_packet;

typedef enum _protocol
{
    PROTOCOL_ARP = 0x0806, // ARP协议
    PROTOCOL_IP = 0x0800,  // IP协议
} protocol_enum;