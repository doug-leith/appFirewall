
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

// file for maintaining state over restarts
#define BLOCKLISTFILE "blocklist.dat"

int get_blocklist_size(void);
bl_item_t* get_blocklist_item(int row);
void add_blockitem(bl_item_t *item);
bl_item_t* in_blocklist_htab(const bl_item_t *item,int debug); // looks up hash table, faster
int del_blockitem(bl_item_t *item);

void save_blocklist(void);
void load_blocklist(void);
void sort_block_list(int asc1, int col);
int bl_sort_cmp(const void* it1, const void* it2);

bl_item_t conn_to_bl_item(const conn_t *item);

char* get_blocklist_item_name(bl_item_t *item);
char* get_blocklist_item_domain(bl_item_t *item);
char* get_blocklist_item_addrname(bl_item_t *item);
char* bl_hash(const void *it);
//int bl_cmp(const void* it1, const void* it2);

#endif /* blocklist_h */
