//
//  dns_sniffer.h
//  appFirewall
//
//  Created by Doug Leith on 05/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef dns_sniffer_h
#define dns_sniffer_h

#include <stdio.h>
#include "libnet.h"
#include <pcap.h>
#include "util.h"
#include "circular_list.h"

typedef struct dns_item_t {
	struct in6_addr addr;
	int af;
	char name[BUFSIZE];
} dns_item_t;

#define DNSFILE "dns.dat"

void dns_sniffer(const struct pcap_pkthdr *pkthdr, const u_char* pkt);
void append_dns(int af, struct in6_addr addr, char* name);
char* lookup_dns_name(int af, struct in6_addr addr);
void load_dns_cache(void);
void save_dns_cache(void);

#endif /* dns_sniffer_h */
