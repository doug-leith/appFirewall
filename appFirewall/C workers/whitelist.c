//
//  whitelist.c
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//


#include "whitelist.h"

// globals
static list_t white_list=LIST_INITIALISER;
static pthread_mutex_t white_mutex = MUTEX_INITIALIZER;

void init_white_list() {
	// caller must hold lock
	// -- only called by load_white_list()
	init_list(&white_list, bl_hash, NULL,  0, -1, "white_list");
}

static bl_item_t res;
bl_item_t *in_whitelist_htab(const bl_item_t *item, int debug) {
	TAKE_LOCK(&white_mutex,"in_whitelist_htab()");
	bl_item_t *res_ptr = in_list(&white_list, item, 0);
	if (res_ptr != NULL) {
		memcpy(&res,res_ptr,sizeof(bl_item_t));
		pthread_mutex_unlock(&white_mutex);
		return &res;
	} else {
		pthread_mutex_unlock(&white_mutex);
		return NULL;
	}
}

void add_whiteitem(bl_item_t *item) {
	if (strcmp(item->name,NOTFOUND)==0) {
		WARN("add_whiteitem() item has process name %s.\n", NOTFOUND);
		return;
	}
	if (strlen(item->domain)==0) {
		WARN("add_whiteitem() item has no domain name.\n");
		return;
	}
	//printf("add_whiteitem %s\n",white_list.hash(item));
	TAKE_LOCK(&white_mutex,"add_whiteitem()");
	add_item(&white_list, item, sizeof(bl_item_t));
	pthread_mutex_unlock(&white_mutex);
	sort_white_list(0, -1);
}

int del_whiteitem(bl_item_t *item) {
	//printf("del_whiteitem %s\n",white_list.hash(item));
	TAKE_LOCK(&white_mutex,"del_whiteitem()");
	del_item(&white_list,item);
	pthread_mutex_unlock(&white_mutex);
	return 0;
}

int_sw get_whitelist_size(void) {
	// only called by GUI
	return (int_sw)get_list_size(&white_list);
}

bl_item_t* get_whitelist_item(int_sw row) {
	// only called by GUI
	return get_list_item(&white_list,(size_t)row);
}

char* get_whitelist_item_name(bl_item_t *item) {
	// only called by GUI
	return item->name;
}

char* get_whitelist_item_domain(bl_item_t *item) {
	// only called by GUI
	return item->domain;
}

char* get_whitelist_item_addrname(bl_item_t *item) {
	// only called by GUI
	return item->addr_name;
}

static int asc=1, col=0;
int wl_sort_cmp(const void* it1, const void* it2){
	bl_item_t **item1 = (bl_item_t**) it1;
	bl_item_t **item2 = (bl_item_t**) it2;
	//printf("%s %s %d\n",(*item1)->name,(*item2)->name,strcasecmp((*item1)->name,(*item2)->name));
	if (col == 0)
		return asc*strcasecmp((*item1)->name,(*item2)->name);
	else
		return asc*strcasecmp((*item1)->domain,(*item2)->domain);
}

void sort_white_list(int asc1, int col1) {
	if ((asc1 != 0) && (asc1 != -1) && (asc1!=1)) { // shouldn't happen
		WARN("sort_white_list() called with asc1=%d\n",asc1);
		return;
	}
	if ((col1!=-1) && (col1!=0) && (col1!=1)) { // shouldn't happen
		WARN("sort_white_list() called with col1=%d\n",col1);
		return;
	}
	if (col1 != -1) {
		col=col1;
	} else {
		col1 = col;
	}
	if (asc1 != 0) {
		if ((asc1 == asc) && (col1 == col)) return; // nothing to do
		asc = asc1; // if asc1==0 we leave asc unchanged
	}
	TAKE_LOCK(&white_mutex,"sort_white_list()");
	sort_list(&white_list, wl_sort_cmp);
	pthread_mutex_unlock(&white_mutex);
}


void save_whitelist(const char* fname) {
	//printf("saving white_list\n");
	#define STR_SIZE 1024
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	
	TAKE_LOCK(&white_mutex,"save_whitelist()");
	save_list(&white_list, path, sizeof(bl_item_t));
	pthread_mutex_unlock(&white_mutex);
}

void load_whitelist(const char* fname) {
	//return;
	INFO("load white list\n");
	// open and read file
	#define STR_SIZE 1024
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	
	TAKE_LOCK(&white_mutex,"load_whitelist()");
	init_white_list();
	load_list(&white_list, path, sizeof(bl_item_t));
	pthread_mutex_unlock(&white_mutex);
	sort_white_list(0, -1);
}
