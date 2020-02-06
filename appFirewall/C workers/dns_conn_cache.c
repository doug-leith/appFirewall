//
//  dns_conn_cache.c
//  appFirewall
//
//  Created by Doug Leith on 03/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "dns_conn_cache.h"

// dns process cache. a list of lists ...
#define MAXDNS 21 // best to be an odd number since we use majority vote
typedef struct dns_conn_t {
	// domain of interest
	char domain[MAXDOMAINLEN];
	// circular list of processes that have used the domain
	char name[MAXDNS][MAXCOMLEN];
	size_t list_start, list_size;
} dns_conn_t;

static list_t dns_conn_list = LIST_INITIALISER;

char* dns_conn_hash(const void* it) {
	dns_conn_t *item = (dns_conn_t*)it;
	char* temp = malloc(MAXDOMAINLEN);
	strlcpy(temp, item->domain, MAXDOMAINLEN);
	return temp;
}

/*void init_dns_conn_list() {
	init_list(&dns_conn_list, dns_conn_hash, NULL,1,-1,"dns_conn_list");
}*/

void add_dns_conn(char* domain, char* name) {
	dns_conn_t item_new;
	strlcpy(item_new.domain, domain, MAXDOMAINLEN);
	strlcpy(item_new.name[0], name, MAXCOMLEN);
	item_new.list_start = 0; item_new.list_size = 1;
	dns_conn_t* it = in_list(&dns_conn_list, &item_new, 0);
	if (it == NULL) {
		// a new domain, add initial entry to list
		add_item(&dns_conn_list,&item_new, sizeof(dns_conn_t));
		return;
	}
	if (it->list_size > MAXDNS) { // shouldn't happen
		WARN("add_dns_conn() list_size %zu > %d\n",it->list_size,MAXDNS);
		while (it->list_size > MAXDNS) {
			it->list_start++; it->list_size--;
		}
	}
	if (it->list_size == MAXDNS) {
		// wrap circular list
		it->list_start++; it->list_size--;
	}
	strlcpy(it->name[(it->list_start+it->list_size)%MAXDNS],name,MAXCOMLEN);
	it->list_size++;
}

void dump_dns_conn_list() {
	list_t *l = &dns_conn_list;
	printf("dns_conn_list start/size: %zu/%zu\n", l->list_start, l->list_size);
	for (size_t i=0; i<get_list_size(l); i++) {
		dns_conn_t *b = get_list_item(l,i);
		printf("%s (%zu): ",b->domain, b->list_size);
		for (size_t j = 0; j< b->list_size; j++) {
			printf("%s ", b->name[(b->list_start+j)%MAXDNS]);
		}
		printf("\n");
	}
}

char* guess_name(char* domain, double* confidence) {
	dns_conn_t item_new;
	strlcpy(item_new.domain, domain, MAXDOMAINLEN);
	dns_conn_t* it = in_list(&dns_conn_list, &item_new, 0);
	if ((it == NULL) || (it->list_size==0)) {
		// no entry for domain in dns_conn list
		*confidence = 0.0;
		return NULL;
	}
	// get a count for each process name that has connected to domain ...
	char *name[MAXDNS];
	size_t count[MAXDNS];
	memset(count,0,sizeof(size_t)*MAXDNS);
	size_t num=0;
	for (size_t i=0; i<it->list_size; i++) {
		size_t index = (it->list_start+i)%MAXDNS;
		int found = 0; size_t j;
		for (j = 0; j< num; j++) {
			if (strcmp(name[j],it->name[index])==0) {
				found = 1; break;
			}
		}
		if (found) {
			count[j]++;
		} else {
			name[num] = it->name[index];
			count[num] = 1;
			num++;
		}
	}
	// now pick the one which has connected most
	size_t max=0, max_posn=0;
	for (size_t i=0; i<num; i++) {
		if (count[i] > max) {
			max = count[i]; max_posn = i;
		}
	}
	// our guess is count[max_posn]
	// rough estimate of our confidence in this gues
	*confidence = max*1.0/it->list_size;
	if (*confidence > 0.95) *confidence = 0.95; // we can't be completely certain
		
	// debugging
	INFO2("GUESSED %s for %s, confidence %f\n", name[max_posn], domain, *confidence);
	//dump_dns_conn_list();
	/*for (size_t i=0; i<it->list_size; i++) {
		printf("%s ",it->name[(i+it->list_start)%MAXDNS]);
	}
	printf("\n");*/
	for (size_t i=0; i<num; i++) {
		INFO2("%s:%zu ", name[i], count[i]);
	}
	INFO2("\n");
	return name[max_posn];
}

void save_dns_conn_list(const char* fname) {
	#define STR_SIZE 1024
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	save_list(&dns_conn_list, path, sizeof(dns_conn_t),DNSCONN_FILE_VERSION);
	//dump_dns_conn_list();
}

int load_dns_conn_list(const char* dir, const char* fname) {
	#define STR_SIZE 1024
	init_list(&dns_conn_list, dns_conn_hash, NULL,1,-1, "dns_conn_list");

	char path[STR_SIZE]; strlcpy(path,dir,STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	FILE *fp = fopen(path,"r");
	if (fp == NULL) return -1; // problem opening file

	load_list(&dns_conn_list, path, sizeof(dns_conn_t), DNSCONN_FILE_VERSION);
	
	// just being careful
	for (size_t i=0; i<get_list_size(&dns_conn_list); i++) {
		dns_conn_t *it = get_list_item(&dns_conn_list,i);
		if ((it->list_size<0) || (it->list_size > MAXDNS)) { // shouldn't happen
			WARN("load_dns_conn_list() list_size %zu > %d or <0, corrupted file? \n",it->list_size,MAXDNS);
			// try to recover ...
			it->list_size = 0;
			it->list_start = 0;
			break;
		}
	}
	
	//dump_dns_conn_list();
	return 0;
}
