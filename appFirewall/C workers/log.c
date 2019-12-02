//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#include "log.h"

// circular list
static list_t log_list=LIST_INITIALISER;

static list_t filtered_log_list=LIST_INITIALISER;
static FILE *fp_txt = NULL; // pointer to human readable log file
static int changed = 0; // flag to record whether log has been updated
static int first_load = 1;

char* log_hash(const void* it) {
	log_line_t* l = (log_line_t*)it;
	char* temp0 = conn_raw_hash(&l->raw);
	size_t len = strlen(temp0)+strlen(l->bl_item.name)+2u;
	if (len>STR_SIZE) len = STR_SIZE;
	char* temp = malloc(len);
	sprintf(temp,"%s:%s",l->bl_item.name,temp0);
	free(temp0);
	return temp;
}

char* filtered_log_hash(const void *it) {
	// this will coalesce multiple connections by same app to same
	// domain that occur within same 1s time slot into a single
	// log entry
	log_line_t* l = (log_line_t*)it;
	size_t len = strlen(l->time_str)+strlen(l->log_line)+4;
	if (len>STR_SIZE) len = STR_SIZE;
	char* temp = malloc(len);
	sprintf(temp,"%s:%s",l->time_str,l->log_line);
	return temp;
}

int_sw has_log_changed(void) {
	return changed;
}

void clear_log_changed(void) {
	changed = 0;
}

size_t get_log_size(void) {
	return get_list_size(&log_list);
}

log_line_t* find_log_by_conn(char* name, conn_raw_t* item, int debug) {
	log_line_t l;
	memcpy(&l.raw,item,sizeof(conn_raw_t));
	strlcpy(l.bl_item.name,name,MAXCOMLEN);
	return in_list(&log_list,&l,0);
}

log_line_t* get_log_row(size_t row) {
	return (log_line_t*)get_list_item(&log_list,row);
}

void log_repeat(log_line_t *l) {
	// we've just tried to add a duplicate entry
	// -- happens when many connection attempts are made in quick succession
	char * loc0 = strstr(l->log_line,"(");
	char * loc1 = strstr(l->log_line,")");
	if ((loc0 != NULL) && (loc1!=NULL) && (loc1>loc0) ) {
		char first_part[LOGSTRSIZE], count_str[LOGSTRSIZE];
		strlcpy(first_part,l->log_line,LOGSTRSIZE);
		first_part[loc0-l->log_line]='\0';
		strlcpy(count_str,loc0+1,LOGSTRSIZE);
		count_str[loc1-loc0-1]='\0';
		int count =atoi(count_str)+1;
		sprintf(l->log_line,"%s(%d)",first_part,count);
	} else {
		char first_part[LOGSTRSIZE];
		strlcpy(first_part,l->log_line,LOGSTRSIZE);
		sprintf(l->log_line,"%s (%d)",first_part,2);
	}
}

void append_log(char* str, char* long_str, struct bl_item_t* bl_item, conn_raw_t *raw, int blocked) {
	changed = 1; // record for GUI fact that log has been updated
	//printf("append_log, %d\n",changed);
	log_line_t *l = malloc(sizeof(log_line_t)+2);
	strlcpy(l->log_line,str,LOGSTRSIZE);
	time_t t; time(&t);
	//str=asctime(localtime(&t)); str[strlen(str)-1]=0; // remove "\n"
	strftime(str,LOGSTRSIZE,"%b %d %H:%M:%S %Y",localtime(&t));
	int len = (int)strlen(str)+1;
	if (len > LOGSTRSIZE) len = LOGSTRSIZE;
	strlcpy(l->time_str, str, len);
	memcpy(&l->bl_item,bl_item,sizeof(struct bl_item_t));
	memcpy(&l->raw,raw,sizeof(conn_raw_t));
	l->blocked = blocked;
	
	add_item(&log_list, l, sizeof(log_line_t));
	
	// and update human-readable log file
	if (fp_txt) {
		fprintf(fp_txt,"%s\t%s\n", l->time_str, long_str);
	} else {
		WARN("Problem appending to %s, re-opening: %s\n", LOGFILE_TXT, strerror(errno));
		char path[STR_SIZE];
		strlcpy(path,get_path(),STR_SIZE); strlcat(path,LOGFILE,STR_SIZE);
		fp_txt = fopen (path,"a");
		if (fp_txt==NULL) {
			WARN("Problem re-opening %s for appending: %s\n", LOGFILE_TXT, strerror(errno));
		}
	}
	free(l); // free our temp copy
}

void clear_log() {
	changed = 2; // record fact that log has been updated
	free_list(&log_list);
	init_list(&log_list,log_hash,NULL,1,-1,"log_list");
}

void filter_log_list(int_sw show_blocked, const char* str) {
	free_list(&filtered_log_list);
	init_list(&filtered_log_list,filtered_log_hash,NULL,1,-1,"filtered_log_list");
	for (size_t i=0; i<get_log_size(); i++) {
		log_line_t *l = get_log_row(i);
		if (l->blocked <= show_blocked) {
			if ((strlen(str)==0) || (strcasestr(l->log_line, str) != NULL)) {
				log_line_t *l_existing = add_item(&filtered_log_list,l,sizeof(log_line_t));
				if (l_existing) log_repeat(l_existing);
			}
		}
	}
}

int_sw get_filter_log_size(void) {
	return (int_sw)get_list_size(&filtered_log_list);
}

log_line_t* get_filter_log_row(int_sw row) {
	return (log_line_t*)get_list_item(&filtered_log_list,(size_t)row);
}

static char _name[INET6_ADDRSTRLEN];
char* get_filter_log_addr_name(int_sw row) {
	log_line_t *l = get_list_item(&filtered_log_list,(size_t)row);
	//char name[INET6_ADDRSTRLEN];
	inet_ntop(l->raw.af,&l->raw.dst_addr,_name,INET6_ADDRSTRLEN);
	return _name;
}

void save_log(void) {
	//printf("saving log\n");
	fflush(fp_txt); // flush text log
	
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE,STR_SIZE);
	save_list(&log_list, path, sizeof(log_line_t));
}

void open_logtxt() {
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE_TXT,STR_SIZE);
	if (fp_txt) close_logtxt();
	fp_txt = fopen (path,"a");
	if (fp_txt==NULL) {
		WARN("Problem opening %s for appending: %s\n", LOGFILE_TXT, strerror(errno));
	}
}

void close_logtxt() {
	if (fp_txt != NULL) fclose(fp_txt);
	fp_txt = NULL;
}

void load_log() {
	changed = 2; // record fact that log has been updated

	close_logtxt();
	open_logtxt(); // will be left open for continuous appending
	
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE,STR_SIZE);
	if (first_load) {
		init_list(&log_list,log_hash,NULL,1,-1,"log_list");
		init_list(&filtered_log_list, filtered_log_hash, NULL,1,-1, "filtered_log_list");
		first_load = 0;
	} else {
		clear_list(&log_list); clear_list(&filtered_log_list);
	}
	//return;
	load_list(&log_list, path, sizeof(log_line_t));
}
