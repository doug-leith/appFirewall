//
//  whitelist.h
//  appFirewall
//


#ifndef whitelist_h
#define whitelist_h

#include <stdio.h>
#include "util.h"
#include "circular_list.h"
#include "blocklist.h"

#define WHITELISTFILE "whitelist.dat"

void init_white_list(void);
bl_item_t *in_whitelist_htab(const bl_item_t *item, int debug);
void add_whiteitem(bl_item_t *item);
int del_whiteitem(bl_item_t *item);
int get_whitelist_size(void);
bl_item_t* get_whitelist_item(int row);
char* get_whitelist_item_name(bl_item_t *item);
char* get_whitelist_item_domain(bl_item_t *item);
char* get_whitelist_item_addrname(bl_item_t *item);
void save_whitelist(void);
void load_whitelist(void);
void sort_white_list(int asc1, int col1);

#endif /* whitelist_h */
