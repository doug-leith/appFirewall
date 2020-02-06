//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "log.h"

// circular list
static list_t log_list=LIST_INITIALISER;
static pthread_mutex_t log_list_mutex = MUTEX_INITIALIZER;

static list_t filtered_log_list=LIST_INITIALISER;
static FILE *fp_txt = NULL; // pointer to human readable log file
static char _logTxtName[STR_SIZE]; // name of file
static int changed = 0; // flag to record whether log has been updated
static int first_load = 1;

char* log_hash(const void* it) {
	log_line_t* l = (log_line_t*)it;
	char* temp0 = conn_raw_hash(&l->raw);
	size_t len = strnlen(temp0,STR_SIZE)+strnlen(l->bl_item.name,MAXCOMLEN)+2u;
	if (len>STR_SIZE) len = STR_SIZE;
	char* temp = malloc(len);
	snprintf(temp,len,"%s:%s",l->bl_item.name,temp0);
	free(temp0);
	return temp;
}

char* filtered_log_hash(const void *it) {
	// this will coalesce multiple connections by same app to same
	// domain that occur within same 1s time slot into a single
	// log entry
	log_line_t* l = (log_line_t*)it;
	size_t len = strnlen(l->time_str,STR_SIZE)+strnlen(l->log_line,STR_SIZE)+4;
	if (len>STR_SIZE) len = STR_SIZE;
	char* temp = malloc(len);
	snprintf(temp,len,"%s:%s",l->time_str,l->log_line);
	return temp;
}

int_sw has_log_changed(void) {
	// only called by GUI
	TAKE_LOCK(&log_list_mutex,"has_log_changed()");
	int_sw res = changed;
	pthread_mutex_unlock(&log_list_mutex);
	return res;
}

void clear_log_changed(void) {
	// only called by GUI
	TAKE_LOCK(&log_list_mutex,"clear_log_changed()");
	changed = 0;
	pthread_mutex_unlock(&log_list_mutex);
}

size_t get_log_size(void) {
	// should hold lock when calling this
	// - only called by filter_log_list() below
	size_t res = get_list_size(&log_list);
 	return res;
}

log_line_t* find_log_by_conn(char* name, conn_raw_t* item, int debug) {
	// take lock here (even though we only append
	// to log, it might wrap around and delete entry)
	// - only called by find_fds() in pid_conn.c
	log_line_t l;
	memcpy(&l.raw,item,sizeof(conn_raw_t));
	strlcpy(l.bl_item.name,name,MAXCOMLEN);
	TAKE_LOCK(&log_list_mutex,"find_log_by_conn()");
	log_line_t* res_ptr =	in_list(&log_list,&l,0);
	if (res_ptr != NULL) {
		log_line_t *res = malloc(sizeof(log_line_t));
		memcpy(res,res_ptr,sizeof(log_line_t));
		pthread_mutex_unlock(&log_list_mutex);
		return res;
	} else {
		pthread_mutex_unlock(&log_list_mutex);
		return NULL;
	}
}

double update_log_line(log_line_t* l, char* name) {
  INFO2("Updating log entry %s: changing name %s->%s, confidence %f->%f\n", l->log_line,l->bl_item.name,name,l->confidence,1.0);
  double prev_conf = l->confidence;
	l->confidence = 1.0;
	strlcpy(l->bl_item.name, name, MAXCOMLEN);
	// remove any question mark from log string
	char* loc = strstr(l->log_line,"?");
	if (loc != NULL) *loc = ' '; // delete the '?'
	return prev_conf;
}

double update_log_by_conn(char* name, conn_raw_t* c, int blocked) {
	// let's see if we can just look up the
	// log line -- will work if we guessed the process name correctly
	// in original log entry
	log_line_t l; double prev_conf = -1.0;
	memcpy(&l.raw,c,sizeof(conn_raw_t));
	strlcpy(l.bl_item.name,name,MAXCOMLEN);
	TAKE_LOCK(&log_list_mutex,"update_log_by_conn()");
	log_line_t* res =	in_list(&log_list,&l,0);
	if (res != NULL) {
		// success!
		prev_conf = update_log_line(res,name);
		pthread_mutex_unlock(&log_list_mutex);
		return prev_conf;
	}
	// failed, let's walk recent log entries ...
	char* temp0 = conn_raw_hash(c);
	#define RECENT_LOG_LINES 50
	for (size_t i = 1; i < RECENT_LOG_LINES; i++) {
		if (i > log_list.list_size) break;
		if (log_list.list_size-i < log_list.list_start) break;
		size_t posn = (log_list.list_size-i)%log_list.maxsize;
		res = log_list.list[posn];
		char* temp1 = conn_raw_hash(&res->raw);
		if (strcmp(temp0,temp1)==0) {
			// we've found an entry with the right connection details
			printf("%0.2f, %s %s\n",res->confidence,res->bl_item.name,name);
			if ((res->confidence >=0.95) && (strcmp(res->bl_item.name,name)!=0)) {
				// different process name, and we're v sure of it, move on
				free(temp1);
				continue;
			}
			// it could be that the source port number has been recycled
			// and so this is a different connection, but we've only checked
			// recent connections so let's take a gamble!
			// start by removing incorrect hash table entry
			del_from_htab(&log_list, res);
			prev_conf = update_log_line(res,name);
			// and now add new hash table entry
			add_item_to_htab(&log_list, res);
			free(temp1);
			break;
		}
		free(temp1);
	}
	free(temp0);
	pthread_mutex_unlock(&log_list_mutex);
	return prev_conf;
}

log_line_t* get_log_row(size_t row) {
	// must hold lock when call this
	// - only called by filter_log_list() below
	log_line_t* res = (log_line_t*)get_list_item(&log_list,row);
	return res;
}

void log_repeat(log_line_t *l) {
	// we've just tried to add a duplicate entry
	// -- happens when many connection attempts are made in quick succession
	// must hold lock when calling
	// - only called by filter_log_list() below
	char * loc0 = strstr(l->log_line,"(");
	char * loc1 = strstr(l->log_line,")");
	if ((loc0 != NULL) && (loc1!=NULL) && (loc1>loc0) ) {
		char first_part[LOGSTRSIZE], count_str[LOGSTRSIZE];
		strlcpy(first_part,l->log_line,LOGSTRSIZE);
		first_part[loc0-l->log_line]='\0';
		strlcpy(count_str,loc0+1,LOGSTRSIZE);
		count_str[loc1-loc0-1]='\0';
		int count =atoi(count_str)+1;
		snprintf(l->log_line,LOGSTRSIZE, "%s(%d)", first_part,count);
	} else {
		char first_part[LOGSTRSIZE];
		strlcpy(first_part,l->log_line,LOGSTRSIZE);
		snprintf(l->log_line, LOGSTRSIZE, "%s (%d)",first_part,2);
	}
}

void append_log(char* str, char* long_str, struct bl_item_t* bl_item, conn_raw_t *raw, int blocked, double confidence) {
	//printf("append_log, %d\n",changed);
	log_line_t *l = calloc(1,sizeof(log_line_t)+2);
	strlcpy(l->log_line,str,LOGSTRSIZE);
	time_t t; time(&t);
	strftime(l->time_str,LOGSTRSIZE,"%b %d %H:%M:%S %Y",localtime(&t));
	memcpy(&l->bl_item,bl_item,sizeof(struct bl_item_t));
	memcpy(&l->raw,raw,sizeof(conn_raw_t));
	l->blocked = blocked;
	l->confidence = confidence;
	
	// might be called from main sniffer_blocker thread or from waiting list
	// thread, so take lock
	TAKE_LOCK(&log_list_mutex,"append_log()");
	changed = 1; // record for GUI fact that log has been updated
	add_item(&log_list, l, sizeof(log_line_t));
	pthread_mutex_unlock(&log_list_mutex);

	// and update human-readable log file
	if (fp_txt != NULL) {
		int res = fprintf(fp_txt,"%s\t%s\n", l->time_str, long_str);
		if (res<=0) {
			WARN("Problem appending to %s, re-opening: %s\n", _logTxtName, strerror(errno));
			reopen_logtxt();
			fprintf(fp_txt,"%s\t%s\n", l->time_str, long_str);
		}
	} else {
		WARN("in append_log() fp_txt = NULL!\n");
	}
	free(l); // free our temp copy
}

void log_connection(conn_raw_t *cr, bl_item_t *c, int blocked, double confidence, char* conf_str, char* service, char* path) {
	char str[LOGSTRSIZE], long_str[LOGSTRSIZE], dn[INET6_ADDRSTRLEN], sn[INET6_ADDRSTRLEN];
	inet_ntop(cr->af, &cr->dst_addr, dn, INET6_ADDRSTRLEN);
	inet_ntop(cr->af, &cr->src_addr, sn, INET6_ADDRSTRLEN);
	char dns[MAXDOMAINLEN], dst_name[MAXDOMAINLEN];
	if (strnlen(c->domain,MAXDOMAINLEN)>0) {
		snprintf(dns, MAXDOMAINLEN, "%s (%s)",c->addr_name,c->domain);
		strlcpy(dst_name,c->domain,MAXDOMAINLEN);
	} else {
		strlcpy(dns,c->addr_name,MAXDOMAINLEN);
		strlcpy(dst_name,c->addr_name,MAXDOMAINLEN);
	}
	snprintf(str, LOGSTRSIZE, "%s%s → %s%s:%u", c->name, conf_str, service, dst_name, cr->dport);
	if (path==NULL) path="";
	snprintf(long_str, LOGSTRSIZE, "%s\t%s%s:%u -> %s:%u\t(blocked=%d, confidence=%.2f)\t%s", c->name, service, sn, cr->sport, dns, cr->dport, blocked, confidence, path);
	append_log(str, long_str, c, cr, blocked, confidence);
}

void clear_log() {
	TAKE_LOCK(&log_list_mutex,"clear_log()");
	changed = 2; // record fact that log has been updated
	free_list(&log_list);
	init_list(&log_list,log_hash,NULL,1,-1,"log_list");
	pthread_mutex_unlock(&log_list_mutex);
}

char* log_conn_str(const void* it) {
	log_line_t* l = (log_line_t*)it;
	char dn[INET6_ADDRSTRLEN];
	robust_inet_ntop(&l->raw.af,&l->raw.dst_addr,dn,INET6_ADDRSTRLEN);
	size_t len = INET6_ADDRSTRLEN+strnlen(l->bl_item.name,MAXDOMAINLEN)+8u;
	if (len>STR_SIZE) len = STR_SIZE;
	char* temp = malloc(len);
	snprintf(temp,len,"%s:%s:%u",l->bl_item.name,dn,l->raw.dport);
	return temp;
}

void filter_log_list(int_sw show_blocked, const char* str) {
	// no need for lock on filtered_log_list, only called by GUI thread
	free_list(&filtered_log_list);
	init_list(&filtered_log_list,filtered_log_hash,NULL,1,-1,"filtered_log_list");
	// hold lock for full loop so that no partial updates are displayed to user
	TAKE_LOCK(&log_list_mutex,"filter_log_list()");
	log_line_t *l=NULL, *l_filtered=NULL;
	char *h=NULL, *h_prev=NULL;
	for (size_t i=0; i< get_log_size(); i++) {
		l = get_log_row(i);
		if (l->blocked <= show_blocked) {
			if ((str==NULL) || (strnlen(str,STR_SIZE)==0) || (strcasestr(l->log_line, str) != NULL)) {
				if (h_prev!=NULL) free(h_prev);
				h_prev=h; h = log_conn_str(l);
				if ((h_prev!=NULL) && (l_filtered!=NULL) && (strcmp(h_prev,h)==0)) {
					// its a repeat line of previous line
					log_repeat(l_filtered);
				} else {
					add_item(&filtered_log_list,l,sizeof(log_line_t));
					l_filtered = in_list(&filtered_log_list,l,0); // keep a pointer to the new entry
					if (l_filtered == NULL) WARN("filter_log_list() couldn't find just added log entry: %s %s\n",l->time_str, l->log_line);
				}
			}
		}
	}
	if (h!=NULL) free(h); if (h_prev!=NULL) free(h_prev);
	pthread_mutex_unlock(&log_list_mutex);
}

int_sw get_filter_log_size(void) {
	// no need for lock, only called by GUI thread
	return (int_sw)get_list_size(&filtered_log_list);
}

log_line_t* get_filter_log_row(int_sw row) {
	// no need for lock, only called by GUI thread
	return (log_line_t*)get_list_item(&filtered_log_list,(size_t)row);
}

static char _name[INET6_ADDRSTRLEN];
char* get_filter_log_addr_name(int_sw row) {
	TAKE_LOCK(&log_list_mutex,"get_filter_log_addr_name()");
	log_line_t *l = get_list_item(&filtered_log_list,(size_t)row);
	//char name[INET6_ADDRSTRLEN];
	inet_ntop(l->raw.af,&l->raw.dst_addr,_name,INET6_ADDRSTRLEN);
	pthread_mutex_unlock(&log_list_mutex);
	return _name;
}

#define NUM_SUGGESTIONS 10
static char suggestions[NUM_SUGGESTIONS][MAXDOMAINLEN] = {0};
static int suggestion_count = 0;
int search_log_domains(const char* str) {
	// returns domains in log that start with str (used by addRule GUI)
	memset(suggestions,0,MAXDOMAINLEN*NUM_SUGGESTIONS);
	suggestion_count = 0;
	for (size_t i=0; i< get_log_size(); i++) {
		log_line_t* l = get_log_row(i);
		char * domain = l->bl_item.domain;
		if ((str==NULL) || (strnlen(str,STR_SIZE)==0) || (strcasestr(domain, str) != NULL)){
			// duplicate ?
			int j;
			for (j=0; j<suggestion_count; j++) {
				if (strcmp(domain,suggestions[j])==0) break;
			}
			if (j==suggestion_count) {
				strlcpy(suggestions[suggestion_count],domain,MAXDOMAINLEN);
				suggestion_count++;
			}
		}
		if (suggestion_count == NUM_SUGGESTIONS) break;
	}
	return suggestion_count;
}

char* get_suggestion(int index) {
	if ((index<0) || (index > suggestion_count)) return NULL;
	return suggestions[index];
}

void save_log(const char* logName) {
	reopen_logtxt();  // reopen rather than flush, then we recover if file deleted
	
	struct timeval s; gettimeofday(&s, NULL);

	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,logName,STR_SIZE);

	TAKE_LOCK(&log_list_mutex,"save_log()");
	save_list(&log_list, path, sizeof(log_line_t),LOG_FILE_VERSION);
	pthread_mutex_unlock(&log_list_mutex);
	
	struct timeval end; gettimeofday(&end, NULL);
	INFO2("save_log() t=%f\n", (end.tv_sec - s.tv_sec) +(end.tv_usec - s.tv_usec)/1000000.0);

}

void open_logtxt(const char* logTxtName) {
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,logTxtName,STR_SIZE);
	strlcpy(_logTxtName, logTxtName, STR_SIZE);
	if (fp_txt) close_logtxt();
	fp_txt = fopen (path,"a");
	if (fp_txt==NULL) {
		WARN("Problem opening %s for appending: %s\n", logTxtName, strerror(errno));
	}
}

void close_logtxt() {
	if (fp_txt != NULL) fclose(fp_txt);
	fp_txt = NULL;
}

void reopen_logtxt() {
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE); strlcat(path,_logTxtName,STR_SIZE);
	if (fp_txt) close_logtxt();
	fp_txt = fopen (path,"a");
	if (fp_txt==NULL) {
		WARN("Problem re-opening %s for appending: %s\n", _logTxtName, strerror(errno));
	}
}

void flush_logtxt() {
	if (fp_txt) fflush(fp_txt);
}

void load_log(const char* logName, const char* logTxtName) {
	close_logtxt();
	open_logtxt(logTxtName); // will be left open for continuous appending
	
	//printf("load_log: %s %s\n", logName, logTxtName);
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,logName,STR_SIZE);
	
	TAKE_LOCK(&log_list_mutex,"load_log()");
	changed = 2; // record fact that log has been updated
	if (first_load) {
		init_list(&log_list,log_hash,NULL,1,-1,"log_list");
		//init_list(&filtered_log_list, filtered_log_hash, NULL,1,-1, "filtered_log_list");
		first_load = 0;
	} else {
		clear_list(&log_list); //clear_list(&filtered_log_list);
	}
	load_list(&log_list, path, sizeof(log_line_t),LOG_FILE_VERSION);
	pthread_mutex_unlock(&log_list_mutex);
}
