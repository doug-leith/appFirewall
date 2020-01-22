//
//  dtrace.c
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "dtrace.h"

// globals
static int d_sock;
static pthread_t thread; // handle to listener thread
static list_t dtrace_cache;
static void (*dtrace_watcher_hook)(void) = NULL;
static pthread_mutex_t dtrace_mutex = MUTEX_INITIALIZER;
int is_running;

int lookup_dtrace(conn_raw_t *cr, char* name, int* pid) {
	// get PID name corresponding to connection cr
	conn_t c;
	c.raw = *cr;
	inet_ntop(c.raw.af,&c.raw.src_addr,c.src_addr_name,INET6_ADDRSTRLEN);
	inet_ntop(c.raw.af,&c.raw.dst_addr,c.dst_addr_name,INET6_ADDRSTRLEN);

	TAKE_LOCK(&dtrace_mutex,"lookup_dtrace()");
	conn_t *res = in_list(&dtrace_cache, &c, 0);
	if (res != NULL) {
		strlcpy(name,res->name,MAXCOMLEN);
		*pid = res->pid;
		pthread_mutex_unlock(&dtrace_mutex);
		return 1;
	}
	pthread_mutex_unlock(&dtrace_mutex);
	return 0;
}

void append_dtrace(conn_t *c) {
	TAKE_LOCK(&dtrace_mutex,"append_dtrace()");
	add_item(&dtrace_cache,c,sizeof(conn_t));
	pthread_mutex_unlock(&dtrace_mutex);
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
	c->raw.af = (int)strtol(item, (char **)NULL, 10);
	if ((c->raw.af != AF_INET) && (c->raw.af !=AF_INET6)) return -1;
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	strlcpy(c->src_addr_name, item,INET6_ADDRSTRLEN);
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	c->raw.sport = (uint16_t)strtol(item, (char **)NULL, 10);
	if (c->raw.sport<0 || c->raw.sport>65535) return -1;
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	strlcpy(c->dst_addr_name, item,INET6_ADDRSTRLEN);
	
	item = strtok_r(NULL, ",", &ptr); if (item == NULL) return -1;
	c->raw.dport = (uint16_t)strtol(item, (char **)NULL, 10);
	if (c->raw.dport<0 || c->raw.dport>65535) return -1;
	
	int res=robust_inet_pton(&c->raw.af,c->src_addr_name,&c->raw.src_addr);
	if (res!=1) {
		WARN("Problem parsing src address from dtrace: %s\n",strerror(errno));
		return -1;
	}
	res=robust_inet_pton(&c->raw.af,c->dst_addr_name,&c->raw.dst_addr);
	if (res!=1) {
		WARN("Problem parsing dst address from dtrace: %s\n",strerror(errno));
		return -1;
	}
	return 0;
}

void set_dtrace_watcher_hook(void (*hook)(void)) {
	dtrace_watcher_hook = hook;
}

void *dtrace_listener(void *ptr) {

  is_running = 1;
	if ( (d_sock=connect_to_helper(DTRACE_PORT,0))<0 ) {
		//fatal error
		is_running =0;
		pthread_exit(NULL);
	}
	
	// disable SIGPIPE, we'll catch such errors ourselves
	signal(SIGPIPE, SIG_IGN);

	size_t inbuf_used = 0; int res=0;
	char inbuf[LINEBUF_SIZE], line[LINEBUF_SIZE];
	conn_t c;
	for(;;) { // we sit in loop waiting for sniffed pkt into from helper
		if ( (res=read_line(d_sock, inbuf, &inbuf_used, line)) <= 0) goto err;
		DEBUG2("dt: %s", line);
		if (parse_dt_line(line, &c)>=0) {
			append_dtrace(&c);
			if (dtrace_watcher_hook != NULL) dtrace_watcher_hook();
		}
		continue;
			
	err:
		if (res == 0) {
			WARN("dtrace connection closed.\n");
		} else if (errno == EOPNOTSUPP) {
			// get this error when code sign check on helper fails, we won't recover from this
			WARN("dtrace: Problem receiving data from helper, likely a code signing issue.\n");
			is_running=0; pthread_exit(NULL);
		} else {
			WARN("dtrace: %s\n", strerror(errno));
		}
		// likely helper has shut down dtrace connection for some reason, reopen it
		close(d_sock); // if don't close and reopen sock we get error
		if ( (d_sock=connect_to_helper(DTRACE_PORT,0))<0 ){
			is_running = 0;
			pthread_exit(NULL);
		}
		continue;
	}
	return NULL;
}

//--------------------------------------------------------
// swift interface

void start_dtrace_listener() {
	// fire up thread that listens for pkts sent by helper
	init_list(&dtrace_cache,conn_hash,NULL,1,-1,"dtrace_cache");	
	pthread_create(&thread, NULL, dtrace_listener, NULL);
}

void stop_dtrace_listener() {
	pthread_kill(thread, SIGTERM);
	close(d_sock);
}

int dtrace_error() {
	return !is_running;
}
