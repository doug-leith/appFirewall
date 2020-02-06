//
//  conn_list.h
//  appFirewall
//
//  Created by Doug Leith on 02/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#ifndef conn_list_h
#define conn_list_h

#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"
#include "connection.h"
#include "circular_list.h"

#define HTABSIZE 250000
#define CONNLIST_FILE_VERSION 1

typedef struct connlist_t {
	list_t conn_list;
	pthread_mutex_t conn_mutex;
	// we keep a separate table of processes for which all conns are blocked
	int connall_list_size, conndomain_list_size;
	Hashtable *connall_htab;
	Hashtable *conndomain_htab;
	char tag[STR_SIZE];
} connlist_t;

#define CONNLIST_INITIALISER {LIST_INITIALISER,MUTEX_INITIALIZER,0,0,NULL,NULL,{0}}
#define BLACKLIST_INITIALISER {LIST_INITIALISER,MUTEX_INITIALIZER,0,0,NULL,NULL,"blacklist"}
#define WHITELIST_INITIALISER {LIST_INITIALISER,MUTEX_INITIALIZER,0,0,NULL,NULL,"whitelist"}

void add_connitem(connlist_t *c, bl_item_t *item);
void add_connitem2(connlist_t *c, const char* name, const char* domain);
void add_connallitem(connlist_t *c, bl_item_t *item);
void add_conndomainitem(connlist_t *c, bl_item_t *item);
bl_item_t* in_connlist_htab(connlist_t *c, const bl_item_t *item,int debug); // looks up hash table, faster
void *in_connalllist_htab(connlist_t *c, const bl_item_t *item, int debug);
void *in_conndomainlist_htab(connlist_t *c, const bl_item_t *item, int debug);
int del_connitem(connlist_t *c, bl_item_t *item);
int cl_sort_cmp(const void* it1, const void* it2);

//swift
bl_item_t conn_to_bl_item(const conn_t *item);
int_sw get_connlist_size(connlist_t *c);
bl_item_t* get_connlist_item(connlist_t *c, int_sw row);
char* get_connlist_item_name(bl_item_t *item);
char* get_connlist_item_domain(bl_item_t *item);
char* get_connlist_item_addrname(bl_item_t *item);
void save_connlist(connlist_t *c, const char* fname);
void load_connlist(connlist_t *c, const char* fname);
void sort_conn_list(connlist_t *c, int_sw asc1, int_sw col);

// lists themselves
connlist_t *get_blocklist(void);
connlist_t *get_whitelist(void);

#endif /* conn_list_h */
