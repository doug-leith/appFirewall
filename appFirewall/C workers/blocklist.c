//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "blocklist.h"

// globals
static list_t block_list=LIST_INITIALISER;
static pthread_mutex_t block_mutex = MUTEX_INITIALIZER;
// we keep a separate table of processes for which all conns are blocked
static int blockall_list_size=0, blockdomain_list_size=0;
static Hashtable *blockall_htab=NULL;
static Hashtable *blockdomain_htab=NULL;

char* bl_hash(const void *it) {
	// generate table lookup key string from block list item
	bl_item_t *item = (bl_item_t*) it;
	size_t len = strnlen(item->name, MAXCOMLEN)+strnlen(item->domain, MAXDOMAINLEN)+4;
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
	if (blockall_htab!=NULL) hashtable_free(blockall_htab);
	blockall_htab = hashtable_new(HTABSIZE);
	blockall_list_size=0;
	blockdomain_htab = hashtable_new(HTABSIZE);
	blockdomain_list_size=0;
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
	// if asc1==0 we re-sort list, used by add_item()
	// if col1==-1 we use same col as before
	if ((asc1 != 0) && (asc1 != -1) && (asc1!=1)) { // shouldn't happen
		WARN("sort_block_list() called with asc1=%d\n",asc1);
		return;
	}
	if ((col1!=-1) && (col1!=0) && (col1!=1)) { // shouldn't happen
		WARN("sort_block_list() called with col1=%d\n",col1);
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
	//printf("sort_block_list: %d/%d col=%d/%d\n",asc,asc1,col,col1);
	TAKE_LOCK(&block_mutex,"sort_block_list()");
	sort_list(&block_list, bl_sort_cmp);
	pthread_mutex_unlock(&block_mutex);
}

static bl_item_t res;
bl_item_t *in_blocklist_htab(const bl_item_t *item, int debug) {
	// called by is_blocked() and by GUI
	TAKE_LOCK(&block_mutex,"in_blocklist_htab()");
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

void *in_blockalllist_htab(const bl_item_t *item, int debug) {
	// called by is_blocked() and by GUI
	TAKE_LOCK(&block_mutex,"in_blockalllist_htab()");
	if (blockall_htab!=NULL) {
		void* res = hashtable_get(blockall_htab, item->name);
		pthread_mutex_unlock(&block_mutex);
		return res;
	}
	pthread_mutex_unlock(&block_mutex);
	return NULL;
}

void add_blockallitem_htab(char *name) {
	printf("add_blockallitem_htab %s\n", name);
	hashtable_put(blockall_htab, name, blockall_htab); // last parameter is just a placeholder
	blockall_list_size++;
}

void add_blockallitem(bl_item_t *item) {
	// take lock so we don't tread on toes of other threads reading list
	TAKE_LOCK(&block_mutex,"add_blockallitem()");
	add_blockallitem_htab(item->name);
	bl_item_t temp;
	strlcpy(temp.name,item->name,MAXCOMLEN);
	strlcpy(temp.domain,ANYDOMAIN,MAXDOMAINLEN);
	strlcpy(temp.addr_name,ANYDOMAIN,INET6_ADDRSTRLEN);
	add_item(&block_list, &temp, sizeof(bl_item_t));
	pthread_mutex_unlock(&block_mutex);
	
	sort_block_list(0, -1); // takes it own lock
}

void *in_blockdomainlist_htab(const bl_item_t *item, int debug) {
	// called by is_blocked() and by GUI
	TAKE_LOCK(&block_mutex,"in_blockdomainlist_htab()");
	if (blockall_htab!=NULL) {
		void* res = hashtable_get(blockdomain_htab, item->domain);
		pthread_mutex_unlock(&block_mutex);
		return res;
	}
	pthread_mutex_unlock(&block_mutex);
	return NULL;
}

void add_blockdomainitem_htab(char *domain) {
	printf("add_blockdomainitem_htab %s\n", domain);
	hashtable_put(blockdomain_htab, domain, blockdomain_htab); // last parameter is just a placeholder
	blockdomain_list_size++;
}

void add_blockdomainitem(bl_item_t *item) {
	// take lock so we don't tread on toes of other threads reading list
	TAKE_LOCK(&block_mutex,"add_blockdomainitem()");
	add_blockdomainitem_htab(item->domain);
	bl_item_t temp;
	memcpy(&temp,item, sizeof(bl_item_t));
	strlcpy(temp.name,ANYAPP,MAXCOMLEN);
	add_item(&block_list, &temp, sizeof(bl_item_t));
	pthread_mutex_unlock(&block_mutex);
	
	sort_block_list(0, -1); // takes it own lock
}

void add_blockitem2(const char* name, const char* domain) {
	bl_item_t item;
	memset(&item,0,sizeof(bl_item_t));
	strlcpy(item.name,name,MAXCOMLEN);
	strlcpy(item.domain,domain,MAXDOMAINLEN);
	add_blockitem(&item);
}

void add_blockitem(bl_item_t *item) {
	// called by GUI
	if (strcmp(item->name,NOTFOUND)==0) {
		WARN("add_blockitem() item has process name %s.\n", NOTFOUND);
		return;
	}
	if (strnlen(item->domain,MAXDOMAINLEN)==0) {
		WARN("add_blockitem() item has no domain name.\n");
		return;
	}
	if (strcmp(item->domain,ANYDOMAIN)==0) {
		// we are blocking all connections for this process
		add_blockallitem(item);
		return;
	}
	if (strcmp(item->name,ANYAPP)==0) {
		// we are blocking all apps for this domaon
		add_blockdomainitem(item);
		return;
	}
	
	// take lock so we don't tread on toes of other threads reading list
	TAKE_LOCK(&block_mutex,"add_blockitem()");
	add_item(&block_list, item, sizeof(bl_item_t));
	pthread_mutex_unlock(&block_mutex);
	sort_block_list(0, -1); // takes it own lock
}

int del_blockitem(bl_item_t *item) {
	// called by GUI
	TAKE_LOCK(&block_mutex,"del_blockitem()");
	if (strcmp(item->domain,ANYDOMAIN)==0) {
		if (blockall_htab == NULL) { // shouldn't happen
			WARN("blockall_htab==NULL in del_blockitem()\n");
		} else {
			if (hashtable_remove(blockall_htab, item->name)!=NULL)
				blockall_list_size--;
		}
	} else if (strcmp(item->name,ANYAPP)==0) {
		if (blockdomain_htab == NULL) { // shouldn't happen
			WARN("blockdomain_htab==NULL in del_blockitem()\n");
		} else {
			if (hashtable_remove(blockdomain_htab, item->domain)!=NULL)
				blockdomain_list_size--;
		}
	}
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

void save_blocklist(const char* fname) {
	//printf("saving block_list\n");
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	TAKE_LOCK(&block_mutex,"save_blocklist()");
	save_list(&block_list, path, sizeof(bl_item_t),BLOCKLIST_FILE_VERSION);
	pthread_mutex_unlock(&block_mutex);
}

void dump_blocklist() {
	// only used for debugging, don't bother with locks
	size_t i;
	for (i=block_list.list_start; i<block_list.list_start+block_list.list_size;i++) {
		bl_item_t *b = (bl_item_t*)&block_list.list[i%block_list.maxsize];
		printf("%s %s\n",b->name,b->domain);
		bl_item_t *res = in_blocklist_htab(b, 0);
		if (res!=NULL) {
			printf("htab: %s %s\n",res->name,res->domain);
		} else {
			printf("htab: absent\n");
		}
	}
}

void load_blocklist(const char* fname) {
	//return;
	// open and read file
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	TAKE_LOCK(&block_mutex,"load_blocklist()");
	init_block_list();
	load_list(&block_list, path, sizeof(bl_item_t),BLOCKLIST_FILE_VERSION);
	size_t i;
	for (i=0; i<get_list_size(&block_list);i++) {
		bl_item_t *b = (bl_item_t*)get_list_item(&block_list,i);
		//printf("%s %s\n", b->name, b->domain);
		if (strcmp(b->domain,ANYDOMAIN)==0) add_blockallitem_htab(b->name);
		if (strcmp(b->name,ANYAPP)==0) add_blockdomainitem_htab(b->domain);
	}
	pthread_mutex_unlock(&block_mutex);
	sort_block_list(0, -1); // takes its own lock
	//dump_blocklist();
}

/*bl_item_t conn_to_bl_item(const conn_t *item) {
		bl_item_t bl;
		strlcpy(bl.name, item->name,MAXCOMLEN);
		strlcpy(bl.addr_name, item->dst_addr_name,INET6_ADDRSTRLEN);
		strlcpy(bl.domain, item->domain,MAXDOMAINLEN);
		return bl;
}*/



