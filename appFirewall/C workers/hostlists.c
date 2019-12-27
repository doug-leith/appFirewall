//
//  hostlists.c
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

// routines for handling host blacklist files e.g. energized_blu

#include "hostlists.h"

static int host_list_size=0;
static Hashtable *hl_htab=NULL; // hash table of pointers into black list for fast lookup
static pthread_mutex_t hl_mutex = MUTEX_INITIALIZER;

void init_hosts_list() {
	// initialise hash table
	if (hl_htab!=NULL) hashtable_free(hl_htab);
	hl_htab = hashtable_new(HTABSIZE);
	
	host_list_size=0;
}

void* in_hostlist_htab(const char *domain) {
	// return values are just NULL or non-NULL, actual values
	// don't matter
	TAKE_LOCK(&hl_mutex,"in_hostlist_htab()");
	if (hl_htab!=NULL) {
		if (!strncmp(domain," (",2)) { // swift adds spaces and () around string, sigh
			char temp[MAXDOMAINLEN];
			strlcpy(temp,domain+2,MAXDOMAINLEN);
			temp[strnlen(temp,MAXDOMAINLEN)-1]=0;
			//printf("in_hostlist_htab swift %s/%s\n", domain, temp);
			void* res = hashtable_get(hl_htab, temp);
			pthread_mutex_unlock(&hl_mutex);
			return res;
		}
		//printf("in_hostlist_htab %s\n", domain[0], domain[1], domain[2], domain);
		void* res = hashtable_get(hl_htab, domain);
		pthread_mutex_unlock(&hl_mutex);
		return res;
	}
	pthread_mutex_unlock(&hl_mutex);
	return NULL;
}

void add_hostlist(char * domain) {
	size_t len = strnlen(domain,MAXDOMAINLEN)+1;
	if (len > STR_SIZE) len = STR_SIZE; // just to be safe !
	char *str = malloc(len);
	strlcpy(str,domain,len);
	TAKE_LOCK(&hl_mutex,"add_hostlist()");
	hashtable_put(hl_htab, str, hl_htab); // last parameter is just a placeholder
	free(str);
	host_list_size++;
	pthread_mutex_unlock(&hl_mutex);
}

int_sw load_hostsfile(const char* fname) {
	// load domain names from hosts file and add to black list table
	
	//printf("load hosts file()\n");
	FILE *  fp = fopen(fname, "r");
	if (fp == NULL) {
			WARN("Problem opening hosts file %s for reading: %s\n", fname, strerror(errno));
			return -1;
	}

	char * line = NULL;
	size_t len = 0;
	ssize_t read;
	while ((read = getline(&line, &len, fp)) != -1) {
			//printf("%s", line);
			// split line using spaces as delimiter
			char* ptr;
			char* addr = strtok_r(line, " ", &ptr);
			if (addr == NULL) continue; // blank line
			if (addr[0] == '#') continue; // comment line
			if ((strncmp(addr,"0.0.0.0",7)!=0) && (strncmp(addr,"127.0.0.1",9)!=0)) continue; // not a blacklist entry
			if (strncmp(addr,"fe80",4)==0)  continue; // IPv6 device local
			if (strncmp(addr,"fe00",4)==0)  continue; // IPv6 device local
			if (strncmp(addr,"fe82",4)==0)  continue; // IPv6 device local
			// get second word, it should be the domain name
			char* domain = strtok_r(NULL, " ", &ptr);
			if (domain == NULL) continue; // no domain name, skip
			if (strcmp(domain,"localhost")==0) continue;
			if (strcmp(domain,"localhost.localdomain")==0) continue;
			if (strcmp(domain,"local")==0) continue;
			if (strcmp(domain,"ip6-localhost")==0) continue;
			if (strcmp(domain,"ip6-loopback")==0) continue;
			// strip any newline
			char * nl = strstr(domain,"\n"); if (nl!=NULL) *nl=0;
			DEBUG2("%s\n", domain);
			// and add domain name to hosts list table
			add_hostlist(domain);
	}
	fclose(fp);
	INFO("loaded %d entries\n",host_list_size);
	if (line) free(line);
	return 0;
}

