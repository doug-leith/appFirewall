//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//


#ifndef blocklist_h
#define blocklist_h

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
#define BLOCKLIST_FILE_VERSION 1

void add_blockitem(bl_item_t *item);
void add_blockitem2(const char* name, const char* domain);
void add_blockallitem(bl_item_t *item);
void add_blockdomainitem(bl_item_t *item);
bl_item_t* in_blocklist_htab(const bl_item_t *item,int debug); // looks up hash table, faster
void *in_blockalllist_htab(const bl_item_t *item, int debug);
void *in_blockdomainlist_htab(const bl_item_t *item, int debug);
int del_blockitem(bl_item_t *item);
int bl_sort_cmp(const void* it1, const void* it2);
char* bl_hash(const void *it);

//swift
//bl_item_t conn_to_bl_item(const conn_t *item);
int_sw get_blocklist_size(void);
bl_item_t* get_blocklist_item(int_sw row);
char* get_blocklist_item_name(bl_item_t *item);
char* get_blocklist_item_domain(bl_item_t *item);
char* get_blocklist_item_addrname(bl_item_t *item);
void save_blocklist(const char* fname);
void load_blocklist(const char* fname);
void sort_block_list(int_sw asc1, int_sw col);

#endif /* blocklist_h */
