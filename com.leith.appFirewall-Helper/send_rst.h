//
//  send_rst.h
//  com.leith.appFirewall-Helper
//
//  Created by Doug Leith on 13/11/2019.
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

void init_libnet(void);
void rst_accept_loop(void);
void close_rst_sock(void);
void snd_rst(int syn, conn_raw_t* c);

#endif /* send_rst_h */
