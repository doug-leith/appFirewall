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

#define RST_PORT 2

typedef struct conn_raw_t {
	int af; // network connection type: IPv4 or IPv6
	struct in6_addr src_addr, dst_addr; // local and remote addresses
	uint16_t sport, dport; // local and remote ports
	int udp;
	uint32_t seq, ack;
	struct timeval ts, start;
} conn_raw_t;

typedef struct libnet_data_t {
	libnet_t *l4, *l6, *l4_hdr, *l6_hdr;  // libnet state
	libnet_ptag_t tcp4_ptag, tcp6_ptag, ip4_ptag, ip6_ptag, tcp4_hdr_ptag, ip4_hdr_ptag,tcp6_hdr_ptag, ip6_hdr_ptag;
} libnet_data_t;

void init_libnet(libnet_data_t *ld);
void start_libnet(void);
void rst_accept_loop(void);
void close_rst_sock(void);
void snd_rst(int syn, conn_raw_t* c, int onlyself, libnet_data_t *ld);

#endif /* send_rst_h */
