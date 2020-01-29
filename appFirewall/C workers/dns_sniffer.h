//
//  dns_sniffer.h
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef dns_sniffer_h
#define dns_sniffer_h

#include <stdio.h>
#include "libnet.h"
#include <pcap.h>
#include "util.h"
#include "circular_list.h"
#include "connection.h"

#define BUFSIZE 1024 // needs to be big enough to hold DNS pkt payload
#define MAXDNS 21
#define DNS_FILE_VERSION 1
#define DNS_CACHE_SIZE 4096 

typedef struct dns_item_t {
	struct in6_addr addr;
	int af;
	char name[MAXDOMAINLEN];
	size_t list_size, list_start;
	char names[MAXDNS][MAXDOMAINLEN]; 
} dns_item_t;

typedef struct dns_count_t {
	char name[MAXDNS][MAXDOMAINLEN];
	size_t num, count[MAXDNS];
} dns_count_t;

int dns_sniffer(const u_char* pkt, size_t pkt_len);
void append_dns(int af, struct in6_addr addr, char* name);
char* lookup_dns_name(int af, struct in6_addr addr);
void reverse_dns_lookup(int af, struct in6_addr addr);

// swift
void load_dns_cache(const char* fname);
void save_dns_cache(const char* fname);
char* get_dns_count_str(int af, struct in6_addr addr);
void dump_dns_cache(void);

#endif /* dns_sniffer_h */
