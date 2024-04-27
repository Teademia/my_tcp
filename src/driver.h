#include <pcap.h>
#include <ether.h>
#include <string.h>
#include <stdlib.h>
pcap_t *open_device(const char *device_name);
net_packet *read_packet(pcap_t *pcap);
net_packet *alloc_packet_for_read();