//
//  connection.c
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "connection.h"

char* conn_raw_hash(const void *it) {
	// generate table lookup key string from conn_raw_t connection tuple
	conn_raw_t *item = (conn_raw_t*) it;
	char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
	robust_inet_ntop(&item->af,&item->src_addr,sn,INET6_ADDRSTRLEN);
	robust_inet_ntop(&item->af,&item->dst_addr,dn,INET6_ADDRSTRLEN);
	#define LEN 2*INET6_ADDRSTRLEN+64
	char* temp = malloc(LEN);
	snprintf(temp,LEN,"%s:%u-%s:%u",sn,item->sport,dn,item->dport);
	return temp;
}

char* conn_hash(const void *it) {
	// generate table lookup key string from conn_t connection tuple
	conn_t* c = (conn_t*) it;
	return conn_raw_hash(&c->raw);
}

char* cl_hash(const void *it) {
	// generate table lookup key string from conn list item
	bl_item_t *item = (bl_item_t*) it;
	size_t len = strnlen(item->name, MAXCOMLEN)+strnlen(item->domain, MAXDOMAINLEN)+4;
	if (len>STR_SIZE) len=STR_SIZE; // just to be safe !
	char* temp = malloc(len);
	strlcpy(temp,item->name, len);
	strlcat(temp,":", len);
	strlcat(temp,item->domain, len);
	return temp;
}

#include "circular_list.h"
void dump_connlist(list_t *l) {
	size_t i;
	for (i=0; i<get_list_size(l);i++) {
		conn_t *b = get_list_item(l,i);
		INFO2("%s(%d): %s:%u -> %s(%s):%u udp=%d\n", b->name, b->pid, b->src_addr_name, b->raw.sport, b->domain, b->dst_addr_name, b->raw.dport, b->raw.udp);
	}
}
