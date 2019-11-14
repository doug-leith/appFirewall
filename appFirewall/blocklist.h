
#ifndef blocklist_h
#define blocklist_h

#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "table.h"
#include "util.h"
#include "pid_conn_info.h"
#include "dtrace.h"

// file for maintaining state over restarts
#define BLOCKLISTFILE "blocklist.dat"

#define MAXBLOCKLIST 1024
typedef struct bl_item_t {
	char name[BUFSIZE]; // name of app associated with connection
	char addr_name[BUFSIZE]; // human-readable form of non-local address
	char domain[BUFSIZE]; // domain name of non-local address, if we know it
} bl_item_t;

int get_blocklist_size(void);
bl_item_t get_blocklist_item(int row);
void add_blockitem(bl_item_t item);
bl_item_t* in_blocklist_htab(const bl_item_t *item,int debug); // looks up hash table, faster
int del_blockitem(bl_item_t item);

void save_blocklist(void);
void load_blocklist(void);
void load_blocklistfile(const char* fname);

bl_item_t conn_to_bl_item(const conn_t *item);
bl_item_t create_blockitem_from_addr(conn_raw_t *cr);

#endif /* blocklist_h */
