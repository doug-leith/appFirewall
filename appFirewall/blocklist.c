
#include "blocklist.h"

// globals
static bl_item_t block_list[MAXBLOCKLIST];
static int block_list_size=0;
// hash table of pointers into block list for fast lookup ...
Hashtable *bl_htab=NULL;
#define STR_SIZE 1024
// stats on dtrace performance (summary: it never misses!) ...
int dtrace_misses=0;

bl_item_t conn_to_bl_item(const conn_t *item) {
		bl_item_t bl;
		strlcpy(bl.name, item->name,BUFSIZE);
		strlcpy(bl.addr_name, item->dst_addr_name,BUFSIZE);
		strlcpy(bl.domain, item->domain,BUFSIZE);
		return bl;
}

char* hash_item(const bl_item_t *item) {
	// generate table lookup key string from block list item
	int len = (int)(strlen(item->name)+strlen(item->domain)+2);
	if (len>STR_SIZE) len=STR_SIZE; // just to be safe !
	char* temp = malloc(len);
	strlcpy(temp,item->name, len);
	strlcat(temp,item->domain, len);
	return temp;
}

bl_item_t * in_blocklist_htab(const bl_item_t *item, int debug) {
	// table lookup of blocklist
	if (block_list_size>0) {
		char *temp = hash_item(item);
		if (debug) { // extra logging requested
			INFO("name=%s, domain=%s, hash_item=%s\n", item->name, item->domain, temp);
			dump_hashtable(bl_htab);
		}
		bl_item_t * res = hashtable_get(bl_htab, temp);
		free(temp);
		return res;
	} else
		return NULL; // not found
}

void add_blockitem_to_htab(bl_item_t *item) {
	// add item to hash table
	char * temp = hash_item(item);
	hashtable_put(bl_htab, temp, item);
	free(temp);
}

bl_item_t create_blockitem_from_addr(conn_raw_t *cr) {
	// create a new blocklist item from raw connection info (assumed to be
	// outgoing connection, so src is local and dst is remote)
	// populates all of blocklist item except for PID name
	bl_item_t c;
	memset(&c,0,sizeof(c));

	// get human readable form of dest adddr
	inet_ntop(cr->af, &cr->dst_addr, c.addr_name, INET6_ADDRSTRLEN);

	// can we get PID from dtrace cache ?
	int res=lookup_dtrace(cr, c.name);
	if (res==0) { // v rare, so interesting
		INFO("%s:%d NOT found in dtrace cache (%d misses), trying procinfo.\n", c.addr_name,cr->sport,dtrace_misses);
		dtrace_misses++;
		// try to get PID info
		res=find_pid(cr,c.name);
		//clock_t end1 = clock();
		if (res==0) {
			strcpy(c.name,"<unknown>");
		}
	} else {
		INFO("%s:%d found in dtrace cache: %s\n",c.addr_name,cr->sport,c.name);
	}

	// try to get domain name from DNS cache
	char* dns =lookup_dns_name(cr->af, cr->dst_addr);
	if (dns!=NULL) {
		strlcpy(c.domain,dns,BUFSIZE);
	}
	
	return c;
}

void del_blockitem_from_htab(bl_item_t *item) {
	char * temp = hash_item(item);
	hashtable_remove(bl_htab, temp);
	free(temp);
}

void add_blockitem(bl_item_t item) {
	if (in_blocklist_htab(&item, 0)) {
		INFO("add_blockitem() item exists.\n");
		return;
	}
	if (strcmp(item.name,"<unknown>")==0) {
		WARN("add_blockitem() item has process name <unknown>.\n");
		return;
	}
	if (strlen(item.domain)==0) {
		WARN("add_blockitem() item has no domain name.\n");
		return;
	}
	if (block_list_size < MAXBLOCKLIST) {
		block_list[block_list_size] = item;
		DEBUG2("%d %s %s\n", block_list_size, item.name, block_list[block_list_size].name);
		block_list_size++;
	} else {
		WARN("add_blockitem() list full.\n");
	}
	add_blockitem_to_htab(&item);
}

int del_blockitem(bl_item_t item) {
	int i,posn;
	for (posn=0; posn<block_list_size; posn++) {
		if  ( (strcmp(block_list[posn].name, item.name) ==0)
				&& (strcmp(block_list[i=posn].domain, item.domain)==0) )
				break; //found a match
	}
	if (posn==block_list_size) {
		INFO("del_blockitem() item not found.\n");
		return -1;
	}
	
	for (i=posn; i<block_list_size-1; i++) {
		block_list[i] = block_list[i+1];
	}
	block_list_size--;
	del_blockitem_from_htab(&item);
	return 0;
}

int get_blocklist_size(void) {
	return block_list_size;
}

bl_item_t get_blocklist_item(int row) {
	return block_list[row];
}

void save_blocklist(void) {
	//printf("saving block_list\n");
	#define STR_SIZE 1024
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,BLOCKLISTFILE,STR_SIZE);
	FILE *fp = fopen(path,"w");
	//char cwd[1024];
	//getcwd(cwd, sizeof(cwd));
	//printf("Current working dir: %s\n", cwd);
	if (fp==NULL) {
		WARN("Problem opening %s for writing: %s\n", BLOCKLISTFILE, strerror(errno));
		return;
	}
	int i;
	int res = (int)fwrite(&block_list_size,sizeof(block_list_size),1,fp);
	if (res<1) {
		WARN("Problem saving size to %s: %s\n", BLOCKLISTFILE,strerror(errno));
		return;
	}
	for(i = 0; i < block_list_size; i++){
		int res=(int)fwrite(&block_list[i],sizeof(bl_item_t),1,fp);
		if (res<1) {
			WARN("Problem saving %s: %s\n", BLOCKLISTFILE, strerror(errno));
			break;
		}
	}
	fclose(fp);
}

void load_blocklist(void) {
	
	// initialise hash table
	if (bl_htab!=NULL) hashtable_free(bl_htab);
	bl_htab = hashtable_new(MAXBLOCKLIST);
	block_list_size = 0;
	//return;

	// open and read file
	#define STR_SIZE 1024
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,BLOCKLISTFILE,STR_SIZE);
	FILE *fp = fopen(path,"r");
	if (fp==NULL) {
		WARN("Problem opening %s for reading: %s\n", BLOCKLISTFILE, strerror(errno));
		return;
	}
	fread(&block_list_size,sizeof(block_list_size),1,fp);
	//printf("block_list_size=%d\n",block_list_size);
	int i;
	for(i = 0; i < block_list_size; i++){
		int res=(int)fread(&block_list[i],sizeof(bl_item_t),1,fp);
		if (res<1) {
			WARN("Problem loading %s: %s", BLOCKLISTFILE, strerror(errno));
			//block_list_size=0;
			break;
		}
		// and put pointer into hash table
		add_blockitem_to_htab(&block_list[i]);
	}
	if (i<block_list_size) {
		WARN("Read too few records from %s: expected %d, got %d\n",BLOCKLISTFILE,block_list_size,i);
		block_list_size = i;
	}
	fclose(fp);
}

char *trimwhitespace(char *str) {
  char *end;

  // Trim leading space
  while(isspace((unsigned char)*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace((unsigned char)*end)) end--;

  // Write new null terminator character
  end[1] = '\0';

  return str;
}

void load_blocklistfile(const char* fname) {
	// load (app,domain) pairs from a file and adds to block list table
	// (so not shown in GUI, which only displays block list itself)
	
	//printf("load block list file()\n");
	FILE *  fp = fopen(fname, "r");
	if (fp == NULL) {
			WARN("Problem opening block list file %s for reading: %s\n", fname, strerror(errno));
			return;
	}

	char * line = NULL;
	size_t len = 0; int count=0;
	ssize_t read;
	while ((read = getline(&line, &len, fp)) != -1) {
			//printf("%s", line);
			// split line using comma as delimiter
			char* ptr;
			char* first = strtok_r(line, ",", &ptr);
			if (first == NULL) continue; // blank line
			if (first[0] == '#') continue; // comment line
			// check first item is not an IP address (i.e. its a host file by
			// mistake !)
			first = trimwhitespace(first);
			struct in_addr addr;
			struct in6_addr addr6;
			if (inet_pton(AF_INET,first,&addr)==1) break; // its an IPv4 address
			if (inet_pton(AF_INET6,first,&addr6)==1) break; // its an IPv6 address
			// looks ok, hopefully its an app process name
			bl_item_t b;
			strlcpy(b.name, first,BUFSIZE);
			
			// get second word, it should be the domain name
			char* domain = strtok_r(NULL, ",", &ptr);
			if (domain == NULL) continue; // no domain name, skip
			domain = trimwhitespace(domain);
			if (!strcmp(domain,"localhost")) continue;
			if (!strcmp(domain,"localhost.localdomain")) continue;
			if (!strcmp(domain,"local")) continue;
			if (!strcmp(domain,"ip6-localhost")) continue;
			if (!strcmp(domain,"ip6-loopback")) continue;
			// strip any newline
			char * nl = strstr(domain,"\n"); if (nl!=NULL) *nl=0;
			DEBUG2("%s\n", domain);
			strlcpy(b.domain, domain, BUFSIZE);

			// and add domain name to hosts list table
			add_blockitem_to_htab(&b);
			count++;
	}
	fclose(fp);
	INFO("loaded %d entries\n",count);
	if (line) free(line);
}

