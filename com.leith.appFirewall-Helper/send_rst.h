//
//  send_rst.h
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef send_rst_h
#define send_rst_h

#include <stdio.h>
#include <netinet/in.h>
#include "libnet.h"
#include <sys/types.h>
#include <net/ethernet.h>
#include "util.h"
#include "conn.h"
#include "pcap_sniffer.h"

#define RST_PORT 2
#define IPV6_SELECT_TIMEOUT 1000 // 1ms in microseconds, for RST rate limiting

typedef struct libnet_data_t {
	libnet_t *l4, *l6;  // libnet state
	libnet_ptag_t tcp4_ptag, tcp6_ptag, ip4_ptag, ip6_ptag, eth_ptag;
	interface_t last_intf;
	uint8_t last_dst_eth[ETHER_ADDR_LEN];
	int toself;
	pcap_t *pd;
} libnet_data_t;

void init_libnet(libnet_data_t *ld);
void free_libnet(libnet_data_t *ld);
void start_rst(void);
void rst_accept_loop(void);
void close_rst_sock(void);
int snd_rst_toself(conn_raw_t* c, libnet_data_t *ld, interface_t* intf);
int snd_rst_toremote(conn_raw_t* c, libnet_data_t *ld, interface_t* intf, int try_data);

#endif /* send_rst_h */
