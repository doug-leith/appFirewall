//
//  whitelist.c
//  appFirewall
//

#include "whitelist.h"

// globals
static list_t white_list=LIST_INITIALISER;

void init_white_list() {
	init_list(&white_list, bl_hash, NULL,  0, -1, "white_list");
}

bl_item_t *in_whitelist_htab(const bl_item_t *item, int debug) {
	return in_list(&white_list, item, 0);
}

void add_whiteitem(bl_item_t *item) {
	if (strcmp(item->name,"<unknown>")==0) {
		WARN("add_whiteitem() item has process name <unknown>.\n");
		return;
	}
	if (strlen(item->domain)==0) {
		WARN("add_whiteitem() item has no domain name.\n");
		return;
	}
	//printf("add_whiteitem %s\n",white_list.hash(item));
	add_item(&white_list, item, sizeof(bl_item_t));
	sort_white_list(0, -1);
}

int del_whiteitem(bl_item_t *item) {
	//printf("del_whiteitem %s\n",white_list.hash(item));
	del_item(&white_list,item);
	return 0;
}

int get_whitelist_size(void) {
	return get_list_size(&white_list);
}

bl_item_t* get_whitelist_item(int row) {
	return get_list_item(&white_list,row);
}

char* get_whitelist_item_name(bl_item_t *item) {
	return item->name;
}

char* get_whitelist_item_domain(bl_item_t *item) {
	return item->domain;
}

char* get_whitelist_item_addrname(bl_item_t *item) {
	return item->addr_name;
}

static int asc=1, col=0;
void sort_white_list(int asc1, int col1) {
	if ((asc1 == -1) || (asc1==1)) asc = asc1;
	if ((col1==0) || (col1==1)) col=col1;
	sort_list(&white_list, bl_sort_cmp);
}

void save_whitelist(void) {
	//printf("saving white_list\n");
	#define STR_SIZE 1024
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,WHITELISTFILE,STR_SIZE);
	save_list(&white_list, path, sizeof(bl_item_t));
}

void load_whitelist(void) {
	init_white_list();
	//return;
	// open and read file
	#define STR_SIZE 1024
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,WHITELISTFILE,STR_SIZE);
	load_list(&white_list, path, sizeof(bl_item_t));
	sort_white_list(0, -1);

}
