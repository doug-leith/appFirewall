//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "blocklist.h"

// globals
static list_t block_list=LIST_INITIALISER;
static pthread_mutex_t block_mutex = PTHREAD_MUTEX_INITIALIZER;

char* bl_hash(const void *it) {
	// generate table lookup key string from block list item
	bl_item_t *item = (bl_item_t*) it;
	size_t len = strlen(item->name)+strlen(item->domain)+4;
	if (len>STR_SIZE) len=STR_SIZE; // just to be safe !
	char* temp = malloc(len);
	strlcpy(temp,item->name, len);
	strlcat(temp,":", len);
	strlcat(temp,item->domain, len);
	return temp;
}

void init_block_list() {
	// must hold lock
	// - only called by load_block_list()
	init_list(&block_list, bl_hash, NULL,  0, -1, "block_list");
}

static int_sw asc=1, col=0;
int bl_sort_cmp(const void* it1, const void* it2){
	bl_item_t **item1 = (bl_item_t**) it1;
	bl_item_t **item2 = (bl_item_t**) it2;
	//printf("%s %s %d\n",(*item1)->name,(*item2)->name,strcasecmp((*item1)->name,(*item2)->name));
	if (col == 0)
		return asc*strcasecmp((*item1)->name,(*item2)->name);
	else
		return asc*strcasecmp((*item1)->domain,(*item2)->domain);
}

void sort_block_list(int asc1, int col1) {
	if ((asc1 == -1) || (asc1==1)) asc = asc1;
	if ((col1==0) || (col1==1)) col=col1;
	pthread_mutex_lock(&block_mutex);
	sort_list(&block_list, bl_sort_cmp);
	pthread_mutex_unlock(&block_mutex);
}

static bl_item_t res;
bl_item_t *in_blocklist_htab(const bl_item_t *item, int debug) {
	// called by is_blocked() and by GUI
	pthread_mutex_lock(&block_mutex);
	bl_item_t * res_ptr = in_list(&block_list, item, debug);
	if (res_ptr != NULL) {
		memcpy(&res,res_ptr,sizeof(bl_item_t));
		pthread_mutex_unlock(&block_mutex);
		return &res;
	} else {
		pthread_mutex_unlock(&block_mutex);
		return NULL;
	}
}

void add_blockitem(bl_item_t *item) {
	// called by GUI
	if (strcmp(item->name,NOTFOUND)==0) {
		WARN("add_blockitem() item has process name %s.\n", NOTFOUND);
		return;
	}
	if (strlen(item->domain)==0) {
		WARN("add_blockitem() item has no domain name.\n");
		return;
	}
	// take lock so we don't tread on toes of other threads reading list
	pthread_mutex_lock(&block_mutex);
	add_item(&block_list, item, sizeof(bl_item_t));
	pthread_mutex_unlock(&block_mutex);
	sort_block_list(0, -1); // takes it own lock
}

int del_blockitem(bl_item_t *item) {
	// called by GUI
	pthread_mutex_lock(&block_mutex);
	del_item(&block_list,item);
	pthread_mutex_unlock(&block_mutex);
	return 0;
}

int_sw get_blocklist_size(void) {
	// called by GUI, which is only thread that changes list
	// so no need for lock
	return (int_sw)get_list_size(&block_list);
}

bl_item_t* get_blocklist_item(int_sw row) {
	// called by GUI, which is only thread that changes list
	// so no need for lock
	return get_list_item(&block_list,(size_t)row);
}

char* get_blocklist_item_name(bl_item_t *item) {
	// called by GUI
	return item->name;
}

char* get_blocklist_item_domain(bl_item_t *item) {
	// called by GUI
	return item->domain;
}

char* get_blocklist_item_addrname(bl_item_t *item) {
	// called by GUI
	return item->addr_name;
}

void save_blocklist(void) {
	//printf("saving block_list\n");
	#define STR_SIZE 1024
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,BLOCKLISTFILE,STR_SIZE);
	pthread_mutex_lock(&block_mutex);
	save_list(&block_list, path, sizeof(bl_item_t));
	pthread_mutex_unlock(&block_mutex);
}

void dump_blocklist() {
	// only used for debugging, don't bother with locks
	size_t i;
	for (i=block_list.list_start; i<block_list.list_start+block_list.list_size;i++) {
		bl_item_t *b = (bl_item_t*)&block_list.list[i%MAXLIST];
		printf("%s %s\n",b->name,b->domain);
		bl_item_t *res = in_blocklist_htab(b, 0);
		if (res!=NULL) {
			printf("htab: %s %s\n",res->name,res->domain);
		} else {
			printf("htab: absent\n");
		}
	}
}

void load_blocklist(void) {
	//return;
	// open and read file
	#define STR_SIZE 1024
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,BLOCKLISTFILE,STR_SIZE);
	pthread_mutex_lock(&block_mutex);
	init_block_list();
	load_list(&block_list, path, sizeof(bl_item_t));
	pthread_mutex_unlock(&block_mutex);
	sort_block_list(0, -1); // takes its own lock
	//dump_blocklist();
}

bl_item_t conn_to_bl_item(const conn_t *item) {
		bl_item_t bl;
		strlcpy(bl.name, item->name,MAXCOMLEN);
		strlcpy(bl.addr_name, item->dst_addr_name,INET6_ADDRSTRLEN);
		strlcpy(bl.domain, item->domain,MAXDOMAINLEN);
		return bl;
}



