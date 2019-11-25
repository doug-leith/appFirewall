//
//  connection.c
//  appFirewall
//

#include "connection.h"

char* conn_raw_hash(const void *it) {
	// generate table lookup key string from conn_raw_t connection tuple
	conn_raw_t *item = (conn_raw_t*) it;
	char sn[INET6_ADDRSTRLEN], dn[INET6_ADDRSTRLEN];
	robust_inet_ntop(&item->af,&item->src_addr,sn,INET6_ADDRSTRLEN);
	robust_inet_ntop(&item->af,&item->dst_addr,dn,INET6_ADDRSTRLEN);
	char* temp = malloc(2*INET6_ADDRSTRLEN+64);
	sprintf(temp,"%s:%u-%s:%u",sn,item->sport,dn,item->dport);
	return temp;
}

char* conn_hash(const void *it) {
	// generate table lookup key string from conn_t connection tuple
	conn_t* c = (conn_t*) it;
	return conn_raw_hash(&c->raw);
}

#include "circular_list.h"
void dump_connlist(list_t *l) {
	int i;
	for (i=0; i<get_list_size(l);i++) {
		conn_t *b = get_list_item(l,i);
		INFO2("%s(%d): %s:%u -> %s(%s):%u udp=%d\n", b->name, b->pid, b->src_addr_name, b->raw.sport, b->domain, b->dst_addr_name, b->raw.dport, b->raw.udp);
	}
}
