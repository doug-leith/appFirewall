//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef sniffer_blocker
#define sniffer_blocker

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <pcap.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <string.h>
#include <pthread.h>
#include "util.h"
#include "pid_conn_info.h"
#include "log.h"
#include "dns_sniffer.h"
#include "libnet.h"
#include "circular_list.h"
#include "connection.h"
#include "dtrace.h"
#include "is_blocked.h"

#define RST_PORT 2
#define PCAP_PORT 3

void init_sniffer_blocker(char* filter_exp);
void sniffer_blocker_callback(u_char *args, const struct pcap_pkthdr *pkthdr, 	const 			u_char* pkt);
bl_item_t create_blockitem_from_addr(conn_raw_t *cr, int syn);

// swift
void start_listener(void);
void stop_listener(void);
int_sw get_num_conns_blocked(void);
void set_num_conns_blocked(int_sw val);
int listener_error(void);

#endif
