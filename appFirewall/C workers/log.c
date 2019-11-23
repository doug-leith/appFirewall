#include "log.h"

// circular list
static list_t log_list;
static list_t filtered_log_list;
static FILE *fp_txt = NULL; // pointer to human readable log file
static int changed = 0; // flag to record whether log has been updated

char* log_hash(const void* it) {
	log_line_t *item = (log_line_t*)it;
	int len = (int)(strlen(item->log_line)+strlen(item->time_str)+4);
	char* temp = malloc(len);
	strlcpy(temp,item->time_str,len);
	strlcat(temp,":",len);
	strlcat(temp,item->log_line,len);
	return temp;
}

int has_log_changed(void) {
	return changed;
}

void clear_log_changed(void) {
	changed = 0;
	//printf("clear_log_changed\n");
}

int get_log_size(void) {
	return get_list_size(&log_list);
}

int find_log_item_row(log_line_t* item) {
	return find_item_row(&log_list, item);
}

log_line_t* get_log_row(int row) {
	return (log_line_t*)get_list_item(&log_list,row);
}

void get_log_addr_name(int row, char* str, int len) {
	log_line_t *l = get_list_item(&log_list,row);
	inet_ntop(l->raw.af,&l->raw.dst_addr,str,len);
	//printf("get_log_addr_name '%s'\n",str);
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
	//printf("append_log: %s %d ",long_str,log_size );
	
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
}

void clear_log() {
	changed = 2; // record fact that log has been updated
	free_list(&log_list);
	init_list(&log_list,log_hash,NULL,1,-1,"log_list");
}

void filter_log_list(int show_blocked, const char* str) {
	free_list(&filtered_log_list);
	init_list(&filtered_log_list,log_hash,NULL,1,-1,"filtered_log_list");
	for (int i=0; i<get_log_size(); i++) {
		log_line_t *l = get_log_row(i);
		if (l->blocked <= show_blocked) {
			if ((strlen(str)==0) || (strcasestr(l->log_line, str) != NULL)) {
				add_item(&filtered_log_list,l,sizeof(log_line_t));
			}
		}
	}
}

int get_filter_log_size(void) {
	return get_list_size(&filtered_log_list);
}

log_line_t* get_filter_log_row(int row) {
	return (log_line_t*)get_list_item(&filtered_log_list,row);
}

void get_filter_log_addr_name(int row, char* str, int len) {
	log_line_t *l = get_list_item(&filtered_log_list,row);
	inet_ntop(l->raw.af,&l->raw.dst_addr,str,len);
}

void save_log(void) {
	//printf("saving log\n");
	fflush(fp_txt); // flush text log
	
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE,STR_SIZE);
	save_list(&log_list, path, sizeof(log_line_t));
}

void load_log() {
	changed = 2; // record fact that log has been updated

	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE_TXT,STR_SIZE);
	fp_txt = fopen (path,"a");
	if (fp_txt==NULL) {
		WARN("Problem opening %s for appending: %s\n", LOGFILE_TXT, strerror(errno));
	}
	
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE,STR_SIZE);
	init_list(&log_list,log_hash,NULL,1,-1,"log_list");
	init_list(&filtered_log_list,log_hash,NULL,1,-1,"filtered_log_list");
	//return;
	load_list(&log_list, path, sizeof(log_line_t));
}
