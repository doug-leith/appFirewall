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
#include "util.h"
#include "conn.h"
#include "pcap_sniffer.h"

#define RST_PORT 2

typedef struct libnet_data_t {
	libnet_t *l4, *l6, *l4_hdr, *l6_hdr;  // libnet state
	libnet_ptag_t tcp4_ptag, tcp6_ptag, ip4_ptag, ip6_ptag, tcp4_hdr_ptag, ip4_hdr_ptag,tcp6_hdr_ptag, ip6_hdr_ptag, eth_ptag;
	char last_intf[STR_SIZE];
} libnet_data_t;

void init_libnet(libnet_data_t *ld);
void start_rst(void);
void rst_accept_loop(void);
void close_rst_sock(void);
int snd_rst_toself(conn_raw_t* c, libnet_data_t *ld, char* intf, uint8_t eth[ETHER_ADDR_LEN]);
int snd_rst_toremote(conn_raw_t* c, libnet_data_t *ld, int try_data);

#endif /* send_rst_h */
