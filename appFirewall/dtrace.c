//
//  dtrace.c
//  appFirewall
//

#include "dtrace.h"

// globals
static int d_sock;
static pthread_t thread; // handle to listener thread
conn_t dtrace_cache[DTRACE_CACHE_SIZE];
int dtrace_cache_size=0, dtrace_cache_start=0;
Hashtable *dt_htab=NULL; // hash table of pointers cache for fast lookup

int lookup_dtrace_row(conn_raw_t *c) {
	int i;
	printf("dtrace start=%d, size=%d\n",dtrace_cache_start,dtrace_cache_size);
	char src_name[INET6_ADDRSTRLEN],dst_name[INET6_ADDRSTRLEN];
	inet_ntop(c->af,&c->src_addr,src_name,INET6_ADDRSTRLEN);
	inet_ntop(c->af,&c->dst_addr,dst_name,INET6_ADDRSTRLEN);
	
	for (i=dtrace_cache_start; i<dtrace_cache_start+dtrace_cache_size; i++) {
		conn_t * item = &dtrace_cache[i%DNS_CACHE_SIZE];
		printf("%d/%d %d/%d %d/%d %s/%s %s/%s\n",c->af,item->af,c->sport,item->sport,c->dport,item->dport,src_name,item->src_name,dst_name,item->dst_name);
		if (item->af != c->af)
			continue;
		if ((c->dport != item->dport) && (c->dport !=item->sport) ) continue;
		if ((c->sport != item->dport) && (c->sport !=item->sport) ) continue;
		if (are_addr_same(c->af,&c->dst_addr,&item->dst_addr)) {
			return i;
		}
	}
	return -1;
}

char* dt_hash_item_raw(conn_raw_t *c) {
	// generate table lookup key string from block list item PID name and dest address
	char src_name[INET6_ADDRSTRLEN],dst_name[INET6_ADDRSTRLEN];
	inet_ntop(c->af,&c->src_addr,src_name,INET6_ADDRSTRLEN);
	inet_ntop(c->af,&c->dst_addr,dst_name,INET6_ADDRSTRLEN);

	int len = (2*INET6_ADDRSTRLEN+64);
	char* temp = malloc(len);
	sprintf(temp,"%s:%d-%s:%d",src_name,c->sport,dst_name,c->dport);
	return temp;
}

char* dt_hash_item(conn_t *c) {
	// generate table lookup key string from block list item PID name and dest address
	int len = (2*INET6_ADDRSTRLEN+64);
	char* temp = malloc(len);
	sprintf(temp,"%s:%d-%s:%d",c->src_name,c->sport,c->dst_name,c->dport);
	return temp;
}

int lookup_dtrace(conn_raw_t *c, char* name) {
	char * temp = dt_hash_item_raw(c);
	conn_t *res = hashtable_get(dt_htab, temp);
	free(temp);
	if (res != NULL) {
		strlcpy(name,res->name,MAXCOMLEN);
		return 1;
	}

	/*
	// old slow way, walk list ...
	int row=lookup_dtrace_row(c);
	if (row>=0) {
		strlcpy(name,dtrace_cache[row%DTRACE_CACHE_SIZE].name,MAXCOMLEN);
		return 1;
	} else {
		return 0;
	}*/
	return 0;

}

void append_dtrace(conn_t *c) {
	if (dtrace_cache_size == DTRACE_CACHE_SIZE) {
		dtrace_cache_start++;
		dtrace_cache_size--;
	}
	int end = dtrace_cache_start+dtrace_cache_size;
	conn_t *item = &dtrace_cache[end%DTRACE_CACHE_SIZE];
	memcpy(item,c,sizeof(conn_t));
	char * temp = dt_hash_item(item);
	hashtable_put(dt_htab, temp, item);
	free(temp);
	dtrace_cache_size++;

}

int parse_dt_line(char* line, conn_t *c) {
	char* ptr;
	//printf("parsing %s\n",line);
	char* item = strtok_r(line, ",", &ptr);
	if (item == NULL) return -1; // blank line
	if (strncmp(item,"<appFirewall>",strlen("<appFirewall>")))  return -1;
	
	// looks ok, let's parse rest of line
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	strlcpy(c->name,item,MAXCOMLEN);
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	c->pid = (int)strtol(item, (char **)NULL, 10);
	if (c->pid <= 0) return -1;
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	c->af = (int)strtol(item, (char **)NULL, 10);
	if ((c->af != AF_INET) && (c->af !=AF_INET6)) return -1;
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	strlcpy(c->src_name, item,INET6_ADDRSTRLEN);
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	c->sport = (int)strtol(item, (char **)NULL, 10);
	if (c->sport<0 || c->sport>65535) return -1;
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	strlcpy(c->dst_name, item,INET6_ADDRSTRLEN);
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	c->dport = (int)strtol(item, (char **)NULL, 10);
	if (c->dport<0 || c->dport>65535) return -1;
	
	if (inet_pton(c->af,c->src_name,&c->src_addr)!=1) return -1;
	if (inet_pton(c->af,c->dst_name,&c->dst_addr)!=1) return -1;
	return 0;
}

void *dtrace_listener(void *ptr) {

	if ( (d_sock=connect_to_helper(DTRACE_PORT))<0 ) {pthread_exit(NULL);} //fatal error
	
	// disable SIGPIPE, we'll catch such errors ourselves
	signal(SIGPIPE, SIG_IGN);

	size_t inbuf_used = 0;
	char inbuf[LINEBUF_SIZE], line[LINEBUF_SIZE];
	conn_t c;
	for(;;) { // we sit in loop waiting for sniffed pkt into from helper
			if (read_line(d_sock, inbuf, &inbuf_used, line) <0) goto err;
			printf("dt: %s", line);
			if (parse_dt_line(line, &c)>=0) {
				append_dtrace(&c);
			}
			continue;
			
	err:
		if (errno==0) {
			WARN("dtrace connection closed.");
		} else {
			WARN("dtrace: %s", strerror(errno));
		}
		// likely helper has shut down dtrace connection for some reason, reopen it
		close(d_sock); // if don't close and reopen sock we get error
		if ( (d_sock=connect_to_helper(DTRACE_PORT))<0 ){
			pthread_exit(NULL); //fatal error
		}
		continue;
	}
	return NULL;
}

//--------------------------------------------------------
// swift interface

void start_dtrace_listener() {
	// fire up thread that listens for pkts sent by helper
	
	if (dt_htab!=NULL) hashtable_free(dt_htab);
	dt_htab = hashtable_new(DTRACE_CACHE_SIZE);
	dtrace_cache_size=0; dtrace_cache_start=0;
	
	pthread_create(&thread, NULL, dtrace_listener, NULL);
}

void stop_dtrace_listener() {
	pthread_kill(thread, SIGTERM);
}
