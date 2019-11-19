
#include "blocklist.h"

// globals
static list_t block_list=LIST_INITIALISER;

#define STR_SIZE 1024
// stats on dtrace performance (summary: it never misses except maybe for
// connections already in progress when app starts up) ...
int dtrace_misses=0;

char* bl_hash(const void *it) {
	// generate table lookup key string from block list item
	bl_item_t *item = (bl_item_t*) it;
	int len = (int)(strlen(item->name)+strlen(item->domain)+2);
	if (len>STR_SIZE) len=STR_SIZE; // just to be safe !
	char* temp = malloc(len);
	strlcpy(temp,item->name, len);
	strlcat(temp,item->domain, len);
	return temp;
}

int bl_cmp(const void* it1, const void* it2){
	bl_item_t *item1 = (bl_item_t*) it1;
	bl_item_t *item2 = (bl_item_t*) it2;
	return ( (strcmp(item1->name,item2->name)==0)
				&& (strcmp(item1->domain,item2->domain)==0) );
}

void init_block_list() {
	init_list(&block_list, bl_hash, bl_cmp,  0, "block_list");
}

static int asc=1, col=0;
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
	sort_list(&block_list, bl_sort_cmp);
}

bl_item_t *in_blocklist_htab(const bl_item_t *item, int debug) {
	return in_list(&block_list, item, debug);
}

void add_blockitem_to_htab(bl_item_t *item) {
	add_item_to_htab(&block_list, item);
}

void del_blockitem_from_htab(const bl_item_t *item) {
	del_from_htab(&block_list, item);
}

void add_blockitem(bl_item_t *item) {
	if (strcmp(item->name,"<unknown>")==0) {
		WARN("add_blockitem() item has process name <unknown>.\n");
		return;
	}
	if (strlen(item->domain)==0) {
		WARN("add_blockitem() item has no domain name.\n");
		return;
	}
	add_item(&block_list, item, sizeof(bl_item_t));
	sort_block_list(0, -1);
}

int del_blockitem(bl_item_t *item) {
	del_item(&block_list,item);
	return 0;
}

int get_blocklist_size(void) {
	return get_list_size(&block_list);
}

bl_item_t* get_blocklist_item(int row) {
	return get_list_item(&block_list,row);
}

char* get_blocklist_item_name(bl_item_t *item) {
	return item->name;
}

char* get_blocklist_item_domain(bl_item_t *item) {
	return item->domain;
}

char* get_blocklist_item_addrname(bl_item_t *item) {
	return item->addr_name;
}

void save_blocklist(void) {
	//printf("saving block_list\n");
	#define STR_SIZE 1024
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,BLOCKLISTFILE,STR_SIZE);
	save_list(&block_list, path, sizeof(bl_item_t));
}

void dump_blocklist() {
	int i;
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
	init_block_list();
	//return;
	// open and read file
	#define STR_SIZE 1024
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,BLOCKLISTFILE,STR_SIZE);
	load_list(&block_list, path, sizeof(bl_item_t));
	sort_block_list(0, -1);

	//dump_blocklist();
}

bl_item_t conn_to_bl_item(const conn_t *item) {
		bl_item_t bl;
		strlcpy(bl.name, item->name,BUFSIZE);
		strlcpy(bl.addr_name, item->dst_addr_name,BUFSIZE);
		strlcpy(bl.domain, item->domain,BUFSIZE);
		return bl;
}

bl_item_t create_blockitem_from_addr(conn_raw_t *cr) {
	// create a new blocklist item from raw connection info (assumed to be
	// outgoing connection, so src is local and dst is remote)
	// populates all of blocklist item except for PID name
	bl_item_t c;
	memset(&c,0,sizeof(c));

	// get human readable form of dest adddr
	inet_ntop(cr->af, &cr->dst_addr, c.addr_name, INET6_ADDRSTRLEN);
	char src[INET6_ADDRSTRLEN];
	inet_ntop(cr->af, &cr->src_addr, src, INET6_ADDRSTRLEN);

	// can we get PID from dtrace cache ?
	int res=lookup_dtrace(cr, c.name);
	if (res==0) { // v rare, so interesting
		INFO("%s:%d->%s:%d NOT found in dtrace cache (%d misses), trying procinfo.\n", src,cr->sport,c.addr_name,cr->dport,dtrace_misses);
		dtrace_misses++;
		// try to get PID info
		res=find_pid(cr,c.name);
		//clock_t end1 = clock();
		if (res==0) {
			strcpy(c.name,"<unknown>");
		}
	} else {
		INFO("%s:%d->%s:%d found in dtrace cache: %s\n",src,cr->sport,c.addr_name,cr->dport,c.name);
	}

	// try to get domain name from DNS cache
	char* dns =lookup_dns_name(cr->af, cr->dst_addr);
	if (dns!=NULL) {
		//printf("dns found for %s\n",dns);
		strlcpy(c.domain,dns,BUFSIZE);
	} else {
		//printf("dns not found for %s\n",c.addr_name);
		strlcpy(c.domain,c.addr_name,INET6_ADDRSTRLEN);
	}
	
	return c;
}


