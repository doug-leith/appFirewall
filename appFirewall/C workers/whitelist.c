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
static int allowall_list_size=0;
static Hashtable *allowall_htab=NULL;
static int allowdomain_list_size=0;
static Hashtable *allowdomain_htab=NULL;


void init_white_list() {
	// caller must hold lock
	// -- only called by load_white_list()
	init_list(&white_list, bl_hash, NULL,  0, -1, "white_list");
	allowall_htab = hashtable_new(HTABSIZE);
	allowall_list_size=0;
	allowdomain_htab = hashtable_new(HTABSIZE);
	allowdomain_list_size=0;
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

void *in_allowalllist_htab(const bl_item_t *item, int debug) {
	// called by is_blocked() and by GUI
	TAKE_LOCK(&white_mutex,"in_allowalllist_htab()");
	if (allowall_htab!=NULL) {
		void* res = hashtable_get(allowall_htab, item->name);
		pthread_mutex_unlock(&white_mutex);
		return res;
	}
	pthread_mutex_unlock(&white_mutex);
	return NULL;
}

void add_allowallitem_htab(char *name) {
	printf("add_allowallitem_htab %s\n", name);
	hashtable_put(allowall_htab, name, allowall_htab); // last parameter is just a placeholder
	allowall_list_size++;
}

void add_allowallitem(bl_item_t *item) {
	// take lock so we don't tread on toes of other threads reading list
	TAKE_LOCK(&white_mutex,"add_allowallitem()");
	add_allowallitem_htab(item->name);
	bl_item_t temp;
	strlcpy(temp.name,item->name,MAXCOMLEN);
	strlcpy(temp.domain,ANYDOMAIN,MAXDOMAINLEN);
	strlcpy(temp.addr_name,ANYDOMAIN,INET6_ADDRSTRLEN);
	add_item(&white_list, &temp, sizeof(bl_item_t));
	pthread_mutex_unlock(&white_mutex);
	
	sort_white_list(0, -1); // takes it own lock
}

void *in_allowdomainlist_htab(const bl_item_t *item, int debug) {
	// called by is_blocked() and by GUI
	TAKE_LOCK(&white_mutex,"in_allowdomainlist_htab()");
	if (allowdomain_htab!=NULL) {
		void* res = hashtable_get(allowdomain_htab, item->domain);
		pthread_mutex_unlock(&white_mutex);
		return res;
	}
	pthread_mutex_unlock(&white_mutex);
	return NULL;
}

void add_allowdomainitem_htab(char *domain) {
	printf("add_allowdomainitem_htab %s\n", domain);
	hashtable_put(allowdomain_htab, domain, allowdomain_htab); // last parameter is just a placeholder
	allowdomain_list_size++;
}

void add_allowdomainitem(bl_item_t *item) {
	// take lock so we don't tread on toes of other threads reading list
	TAKE_LOCK(&white_mutex,"add_allowdomainitem()");
	add_allowdomainitem_htab(item->domain);
	bl_item_t temp;
	memcpy(&temp,item,sizeof(bl_item_t));
	strlcpy(temp.name,ANYAPP,MAXCOMLEN);
	add_item(&white_list, &temp, sizeof(bl_item_t));
	pthread_mutex_unlock(&white_mutex);
	
	sort_white_list(0, -1); // takes it own lock
}

void add_whiteitem2(const char* name, const char* domain) {
	bl_item_t item;
	memset(&item,0,sizeof(bl_item_t));
	strlcpy(item.name,name,MAXCOMLEN);
	strlcpy(item.domain,domain,MAXDOMAINLEN);
	add_whiteitem(&item);
}

void add_whiteitem(bl_item_t *item) {
	if (strcmp(item->name,NOTFOUND)==0) {
		WARN("add_whiteitem() item has process name %s.\n", NOTFOUND);
		return;
	}
	if (strnlen(item->domain,MAXDOMAINLEN)==0) {
		WARN("add_whiteitem() item has no domain name.\n");
		return;
	}
	if (strcmp(item->domain,ANYDOMAIN)==0) {
		// we are allowing all connections for this process
		add_allowallitem(item);
		return;
	}
	if (strcmp(item->name,ANYAPP)==0) {
		// we are allowing all connections for this domain
		add_allowdomainitem(item);
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
	if (strcmp(item->domain,ANYDOMAIN)==0) {
		if (allowall_htab == NULL) { // shouldn't happen
			WARN("allowall_htab==NULL in del_whiteitem()\n");
		} else {
			if (hashtable_remove(allowall_htab, item->name)!=NULL)
				allowall_list_size--;
		}
	} else if (strcmp(item->name,ANYAPP)==0) {
		if (allowdomain_htab == NULL) { // shouldn't happen
			WARN("allowdomain_htab==NULL in del_whiteitem()\n");
		} else {
			if (hashtable_remove(allowdomain_htab, item->domain)!=NULL)
				allowdomain_list_size--;
		}
	}
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
	save_list(&white_list, path, sizeof(bl_item_t),WHITELIST_FILE_VERSION);
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
	load_list(&white_list, path, sizeof(bl_item_t),WHITELIST_FILE_VERSION);
	size_t i;
	for (i=0; i<get_list_size(&white_list);i++) {
		bl_item_t *b = (bl_item_t*)get_list_item(&white_list,i);
		//printf("%s %s\n", b->name, b->domain);
		if (strcmp(b->domain,ANYDOMAIN)==0) add_allowallitem_htab(b->name);
		if (strcmp(b->name,ANYAPP)==0) add_allowdomainitem_htab(b->domain);
	}
	pthread_mutex_unlock(&white_mutex);
	sort_white_list(0, -1);
}
