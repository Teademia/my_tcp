#include "xnet_tiny.h"
xnet_err_t xnet_driver_open(uint8_t *mac_addr);
xnet_err_t xnet_driver_send(xnet_packet_t *packet);
xnet_err_t xnet_driver_read(xnet_packet_t **packet);