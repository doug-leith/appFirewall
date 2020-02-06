//
//  conn_list.c
//  appFirewall
//
//  Created by Doug Leith on 02/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#include "conn_list.h"

// globals
static connlist_t blocklist = BLACKLIST_INITIALISER;
static connlist_t whitelist = WHITELIST_INITIALISER;

connlist_t *get_blocklist() {
	return &blocklist;
}

connlist_t *get_whitelist() {
	return &whitelist;
}

void init_conn_list(connlist_t *c) {
	// must hold lock
	// - only called by load_conn_list()
	init_list(&c->conn_list, cl_hash, NULL,  0, -1, c->tag);
	if (c->connall_htab!=NULL) hashtable_free(c->connall_htab);
	c->connall_htab = hashtable_new(HTABSIZE);
	c->connall_list_size=0;
	c->conndomain_htab = hashtable_new(HTABSIZE);
	c->conndomain_list_size=0;
}

static int_sw asc=1, col=0;
int cl_sort_cmp(const void* it1, const void* it2){
	bl_item_t **item1 = (bl_item_t**) it1;
	bl_item_t **item2 = (bl_item_t**) it2;
	//printf("%s %s %d\n",(*item1)->name,(*item2)->name,strcasecmp((*item1)->name,(*item2)->name));
	if (col == 0)
		return asc*strcasecmp((*item1)->name,(*item2)->name);
	else
		return asc*strcasecmp((*item1)->domain,(*item2)->domain);
}

void sort_conn_list(connlist_t *c, int asc1, int col1) {
	// if asc1==0 we re-sort list, used by add_item()
	// if col1==-1 we use same col as before
	if ((asc1 != 0) && (asc1 != -1) && (asc1!=1)) { // shouldn't happen
		WARN("sort_conn_list() called for %s with asc1=%d\n",c->tag,asc1);
		return;
	}
	if ((col1!=-1) && (col1!=0) && (col1!=1)) { // shouldn't happen
		WARN("sort_conn_list() called for %s with col1=%d\n",c->tag,col1);
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
	//printf("sort_conn_list: %d/%d col=%d/%d\n",asc,asc1,col,col1);
	TAKE_LOCK(&c->conn_mutex,"sort_conn_list()");
	sort_list(&c->conn_list, cl_sort_cmp);
	pthread_mutex_unlock(&c->conn_mutex);
}

static bl_item_t res;
bl_item_t *in_connlist_htab(connlist_t *c, const bl_item_t *item, int debug) {
	// called by is_conned() and by GUI
	TAKE_LOCK(&c->conn_mutex,"in_connlist_htab()");
	bl_item_t * res_ptr = in_list(&c->conn_list, item, debug);
	if (res_ptr != NULL) {
		memcpy(&res,res_ptr,sizeof(bl_item_t));
		pthread_mutex_unlock(&c->conn_mutex);
		return &res;
	} else {
		pthread_mutex_unlock(&c->conn_mutex);
		return NULL;
	}
}

void *in_connalllist_htab(connlist_t *c, const bl_item_t *item, int debug) {
	// called by is_conned() and by GUI
	TAKE_LOCK(&c->conn_mutex,"in_connalllist_htab()");
	if (c->connall_htab!=NULL) {
		void* res = hashtable_get(c->connall_htab, item->name);
		pthread_mutex_unlock(&c->conn_mutex);
		return res;
	}
	pthread_mutex_unlock(&c->conn_mutex);
	return NULL;
}

void add_connallitem_htab(connlist_t *c, char *name) {
	printf("add_connallitem_htab %s to %s\n", name, c->tag);
	hashtable_put(c->connall_htab, name, c->connall_htab); // last parameter is just a placeholder
	c->connall_list_size++;
}

void add_connallitem(connlist_t *c, bl_item_t *item) {
	// take lock so we don't tread on toes of other threads reading list
	TAKE_LOCK(&c->conn_mutex,"add_connallitem()");
	add_connallitem_htab(c,item->name);
	bl_item_t temp;
	strlcpy(temp.name,item->name,MAXCOMLEN);
	strlcpy(temp.domain,ANYDOMAIN,MAXDOMAINLEN);
	strlcpy(temp.addr_name,ANYDOMAIN,INET6_ADDRSTRLEN);
	add_item(&c->conn_list, &temp, sizeof(bl_item_t));
	pthread_mutex_unlock(&c->conn_mutex);
	
	sort_conn_list(c,0, -1); // takes it own lock
}

void *in_conndomainlist_htab(connlist_t *c, const bl_item_t *item, int debug) {
	// called by is_blocked() and by GUI
	TAKE_LOCK(&c->conn_mutex,"in_conndomainlist_htab()");
	if (c->connall_htab!=NULL) {
		void* res = hashtable_get(c->conndomain_htab, item->domain);
		pthread_mutex_unlock(&c->conn_mutex);
		return res;
	}
	pthread_mutex_unlock(&c->conn_mutex);
	return NULL;
}

void add_conndomainitem_htab(connlist_t *c, char *domain) {
	printf("add_conndomainitem_htab %s for %s\n", domain, c->tag);
	hashtable_put(c->conndomain_htab, domain, c->conndomain_htab); // last parameter is just a placeholder
	c->conndomain_list_size++;
}

void add_conndomainitem(connlist_t *c, bl_item_t *item) {
	// take lock so we don't tread on toes of other threads reading list
	TAKE_LOCK(&c->conn_mutex,"add_conndomainitem()");
	add_conndomainitem_htab(c,item->domain);
	bl_item_t temp;
	memcpy(&temp,item, sizeof(bl_item_t));
	strlcpy(temp.name,ANYAPP,MAXCOMLEN);
	add_item(&c->conn_list, &temp, sizeof(bl_item_t));
	pthread_mutex_unlock(&c->conn_mutex);
	
	sort_conn_list(c,0, -1); // takes it own lock
}

void add_connitem2(connlist_t *c, const char* name, const char* domain) {
	bl_item_t item;
	memset(&item,0,sizeof(bl_item_t));
	strlcpy(item.name,name,MAXCOMLEN);
	strlcpy(item.domain,domain,MAXDOMAINLEN);
	add_connitem(c,&item);
}

void add_connitem(connlist_t *c, bl_item_t *item) {
	// called by GUI
	if (strcmp(item->name,NOTFOUND)==0) {
		WARN("add_connitem() item for %s has process name %s.\n", c->tag, NOTFOUND);
		return;
	}
	if (strnlen(item->domain,MAXDOMAINLEN)==0) {
		WARN("add_connitem() for %s item has no domain name.\n",c->tag);
		return;
	}
	if (strcmp(item->domain,ANYDOMAIN)==0) {
		// we are conning all connections for this process
		add_connallitem(c,item);
		return;
	}
	if (strcmp(item->name,ANYAPP)==0) {
		// we are conning all apps for this domaon
		add_conndomainitem(c,item);
		return;
	}
	
	// take lock so we don't tread on toes of other threads reading list
	TAKE_LOCK(&c->conn_mutex,"add_connitem()");
	add_item(&c->conn_list, item, sizeof(bl_item_t));
	pthread_mutex_unlock(&c->conn_mutex);
	sort_conn_list(c,0, -1); // takes it own lock
}

int del_connitem(connlist_t *c, bl_item_t *item) {
	// called by GUI
	TAKE_LOCK(&c->conn_mutex,"del_connitem()");
	if (strcmp(item->domain,ANYDOMAIN)==0) {
		if (c->connall_htab == NULL) { // shouldn't happen
			WARN("connall_htab==NULL in del_connitem() for %s\n",c->tag);
		} else {
			if (hashtable_remove(c->connall_htab, item->name)!=NULL)
				c->connall_list_size--;
		}
	} else if (strcmp(item->name,ANYAPP)==0) {
		if (c->conndomain_htab == NULL) { // shouldn't happen
			WARN("conndomain_htab==NULL in del_connitem() for %s\n",c->tag);
		} else {
			if (hashtable_remove(c->conndomain_htab, item->domain)!=NULL)
				c->conndomain_list_size--;
		}
	}
	del_item(&c->conn_list,item);
	pthread_mutex_unlock(&c->conn_mutex);
	return 0;
}

int_sw get_connlist_size(connlist_t *c) {
	// called by GUI, which is only thread that changes list
	// so no need for lock
	return (int_sw)get_list_size(&c->conn_list);
}

bl_item_t* get_connlist_item(connlist_t *c, int_sw row) {
	// called by GUI, which is only thread that changes list
	// so no need for lock
	return get_list_item(&c->conn_list,(size_t)row);
}

char* get_connlist_item_name(bl_item_t *item) {
	// called by GUI
	return item->name;
}

char* get_connlist_item_domain(bl_item_t *item) {
	// called by GUI
	return item->domain;
}

char* get_connlist_item_addrname(bl_item_t *item) {
	// called by GUI
	return item->addr_name;
}

void save_connlist(connlist_t *c, const char* fname) {
	//printf("saving conn_list\n");
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	TAKE_LOCK(&c->conn_mutex,"save_connlist()");
	save_list(&c->conn_list, path, sizeof(bl_item_t),CONNLIST_FILE_VERSION);
	pthread_mutex_unlock(&c->conn_mutex);
}

void dump_connlist_all(connlist_t *c) {
	// only used for debugging, don't bother with locks
	size_t i;
	for (i=c->conn_list.list_start; i<c->conn_list.list_start+c->conn_list.list_size;i++) {
		bl_item_t *b = (bl_item_t*)&c->conn_list.list[i%c->conn_list.maxsize];
		printf("%s %s\n",b->name,b->domain);
		bl_item_t *res = in_connlist_htab(c,b, 0);
		if (res!=NULL) {
			printf("htab: %s %s\n",res->name,res->domain);
		} else {
			printf("htab: absent\n");
		}
	}
}

void load_connlist(connlist_t *c, const char* fname) {
	//return;
	// open and read file
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,fname,STR_SIZE);
	TAKE_LOCK(&c->conn_mutex,"load_connlist()");
	init_conn_list(c);
	load_list(&c->conn_list, path, sizeof(bl_item_t),CONNLIST_FILE_VERSION);
	size_t i;
	for (i=0; i<get_list_size(&c->conn_list);i++) {
		bl_item_t *b = (bl_item_t*)get_list_item(&c->conn_list,i);
		//printf("%s %s\n", b->name, b->domain);
		if (strcmp(b->domain,ANYDOMAIN)==0) add_connallitem_htab(c,b->name);
		if (strcmp(b->name,ANYAPP)==0) add_conndomainitem_htab(c,b->domain);
	}
	pthread_mutex_unlock(&c->conn_mutex);
	sort_conn_list(c,0, -1); // takes its own lock
	//dump_connlist_all();
}

bl_item_t conn_to_bl_item(const conn_t *item) {
		bl_item_t bl;
		strlcpy(bl.name, item->name,MAXCOMLEN);
		strlcpy(bl.addr_name, item->dst_addr_name,INET6_ADDRSTRLEN);
		strlcpy(bl.domain, item->domain,MAXDOMAINLEN);
		return bl;
}



