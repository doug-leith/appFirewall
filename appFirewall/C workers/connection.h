//
//  connection.h
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef connection_h
#define connection_h

#include <stdio.h>
#include <libproc.h>
#include <arpa/inet.h>
#include "util.h"
#include "circular_list.h"

typedef struct conn_raw_t {
	int af; // network connection type: IPv4 or IPv6
	struct in6_addr src_addr, dst_addr; // local and remote addresses
	uint16_t sport, dport; // local and remote ports
	int udp;
	uint32_t seq, ack;
	struct timeval ts, start;
} conn_raw_t;

#define MAXDOMAINLEN 256 //max length of an domain name is 253 chars, and round up

typedef struct conn_t {
	int pid, fd; // PID of process associated with connection, and socket file descriptor
	char name[MAXCOMLEN]; // Name of process associated with connection
	conn_raw_t raw;
	char domain[MAXDOMAINLEN]; // domain name of remote addr
	char src_addr_name[INET6_ADDRSTRLEN], dst_addr_name[INET6_ADDRSTRLEN];
} conn_t;

// bl_item_t is used by swift
typedef struct bl_item_t {
	char name[MAXCOMLEN]; // name of app associated with connection
	char addr_name[INET6_ADDRSTRLEN]; // human-readable form of non-local address
	char domain[MAXDOMAINLEN]; // domain name of non-local address, if we know it
} bl_item_t;

char* conn_raw_hash(const void *it);
char* conn_hash(const void *it);
char* cl_hash(const void *it);
void dump_connlist(list_t *l);

#endif /* connection_h */
