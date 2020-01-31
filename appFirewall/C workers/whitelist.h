//
//  whitelist.h
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//


#ifndef whitelist_h
#define whitelist_h

#include <stdio.h>
#include "util.h"
#include "circular_list.h"
#include "blocklist.h"

#define HTABSIZE 250000
#define WHITELIST_FILE_VERSION 1

void init_white_list(void);
bl_item_t *in_whitelist_htab(const bl_item_t *item, int debug);
void *in_allowalllist_htab(const bl_item_t *item, int debug);
void *in_allowdomainlist_htab(const bl_item_t *item, int debug);
void add_whiteitem(bl_item_t *item);
void add_whiteitem2(const char* name, const char* domain);
void add_allowallitem(bl_item_t *item);
void add_allowdomainitem(bl_item_t *item);
int del_whiteitem(bl_item_t *item);

// swift
void save_whitelist(const char* fname);
void load_whitelist(const char* fname);
void sort_white_list(int_sw asc1, int_sw col1);
int_sw get_whitelist_size(void);
bl_item_t* get_whitelist_item(int_sw row);
char* get_whitelist_item_name(bl_item_t *item);
char* get_whitelist_item_domain(bl_item_t *item);
char* get_whitelist_item_addrname(bl_item_t *item);

#endif /* whitelist_h */
