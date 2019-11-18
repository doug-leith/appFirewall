#include "log.h"

// circular list
list_t log_list;
FILE *fp_txt = NULL; // pointer to human readable log file
int changed = 0; // flag to record whether log has been updated
#define STR_SIZE 1024

char* log_hash(const void* it) {
	log_line_t *item = (log_line_t*)it;
	int len = (int)(strlen(item->log_line)+strlen(item->time_str));
	char* temp = malloc(len);
	strlcpy(temp,item->time_str,len);
	strlcat(temp,item->log_line,len);
	return temp;
}

int log_cmp(const void* it1, const void* it2) {
	log_line_t *item1 = (log_line_t*)it1;
	log_line_t *item2 = (log_line_t*)it2;
	return ((strcmp(item1->time_str, item2->time_str)==0)
					&& (strcmp(item1->log_line, item2->log_line)==0) );
}

int has_log_changed(void) {
	return changed;
}

void clear_log_changed(void) {
	changed = 0;
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
	log_line_t *l = malloc(sizeof(log_line_t));
	strlcpy(l->log_line,str,LOGSTRSIZE);
	time_t t; time(&t);
	str=asctime(localtime(&t)); str[strlen(str)-1]=0; // remove "\n"
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
	changed = 1; // record fact that log has been updated
	free_list(&log_list);
	init_list(&log_list,log_hash,log_cmp,0);
}

void save_log(void) {
	//printf("saving log\n");
	fflush(fp_txt); // flush text log
	
	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE,STR_SIZE);
	save_list(&log_list, path, sizeof(log_line_t));

	/*FILE *fp = fopen (path,"w+");
	if (fp==NULL) {
		WARN("Problem opening %s for writing: %s\n", LOGFILE, strerror(errno));
		return;
	}
	//
	int res = (int)fwrite(&log_start,sizeof(log_start),1,fp);
	if (res<1) {
		ERR("Problem saving start to %s: %s\n", LOGFILE,strerror(errno));
		return;
	}
	res = (int)fwrite(&log_size,sizeof(log_size),1,fp);
	if (res<1) {
		ERR("Problem saving size to %s: %s\n", LOGFILE,strerror(errno));
		return;
	}
	int i;
	for(i = log_start; i < log_start+log_size; i++){
		int res = (int)fwrite(&log_lines[i%MAXLOGSIZE].blocked,sizeof(int),1,fp);
		if (res<1) {
			WARN("Problem saving to %s: %s\n", LOGFILE,strerror(errno));
			break;
		}
		int len = (int)strlen(log_lines[i%MAXLOGSIZE].time_str);
		fwrite(&len,sizeof(len),1,fp);
		fwrite(log_lines[i%MAXLOGSIZE].time_str,len,1,fp);
		len = (int)strlen(log_lines[i%MAXLOGSIZE].log_line);
		fwrite(&len,sizeof(len),1,fp);
		fwrite(log_lines[i%MAXLOGSIZE].log_line,len,1,fp);
		fwrite(&log_lines[i%MAXLOGSIZE].bl_item,sizeof(struct bl_item_t),1,fp);
		res = (int)fwrite(&log_lines[i%MAXLOGSIZE].raw,sizeof(struct conn_raw_t),1,fp);
		if (res<1) {
			WARN("Problem saving to %s: %s\n", LOGFILE,strerror(errno));
			break;
		}
	}
	fclose(fp);
	*/
}

void load_log() {
	changed = 1; // record fact that log has been updated

	char path[STR_SIZE];
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE_TXT,STR_SIZE);
	fp_txt = fopen (path,"a");
	if (fp_txt==NULL) {
		WARN("Problem opening %s for appending: %s\n", LOGFILE_TXT, strerror(errno));
	}
	
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE,STR_SIZE);
	init_list(&log_list,log_hash,log_cmp,0);
	load_list(&log_list, path, sizeof(log_line_t));
	
	/*fp_txt = fopen (path,"a");
	if (fp_txt==NULL) {
		WARN("Problem opening %s for appending: %s\n", LOGFILE_TXT, strerror(errno));
	}
	
	strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE,STR_SIZE);
	FILE *fp = fopen (path,"r");
	if (fp==NULL) {
		WARN("Problem opening %s for reading: %s\n", LOGFILE, strerror(errno));
		log_start=0; log_size=0;
		return;
	}
	//return;
	int i;
	int res=(int)fread(&log_start,sizeof(log_start),1,fp);
	if (res<1 || log_start<0) {
		WARN("Problem loading log_start from %s: %s", LOGFILE, strerror(errno));
		log_start=0; log_size=0;
		return;
	}
	res=(int)fread(&log_size,sizeof(log_size),1,fp);
	if (res<1 || log_size>MAXLOGSIZE) {
		WARN("Problem loading log_size from %s: %s", LOGFILE, strerror(errno));
		log_start=0; log_size=0;
		return;
	}
	DEBUG2("log_start=%d, log_size=%d\n",log_start,log_size);
	log_start=0; // might as well reset this since we're loading a fresh copy of log
	for(i = 0; i < log_size; i++){
		int res = (int)fread(&log_lines[i%MAXLOGSIZE].blocked,sizeof(int),1,fp);
		if (res<1) {
			WARN("Problem loading blocked from %s: %s\n", LOGFILE,strerror(errno));
			break;
		}
		int len;
		res = (int)fread(&len,sizeof(len),1,fp);
		if (res<1 || (len > STR_SIZE) ) {
			WARN("Problem loading time_str len from %s: %s\n", LOGFILE,strerror(errno));
			break;
		}
		log_lines[i%MAXLOGSIZE].time_str = calloc(1,len+1);
		res = (int)fread(log_lines[i%MAXLOGSIZE].time_str,len,1,fp);
		if (res<1 || (len > STR_SIZE)) {
			WARN("Problem loading time_str from %s: %s\n", LOGFILE,strerror(errno));
			break;
		}
		res = (int)fread(&len,sizeof(len),1,fp);
		if (res<1 || (len > STR_SIZE)) {
			WARN("Problem loading log_line len from %s: %s\n", LOGFILE,strerror(errno));
			break;
		}
		log_lines[i%MAXLOGSIZE].log_line = calloc(1,len+1);
		res = (int)fread(log_lines[i%MAXLOGSIZE].log_line,len,1,fp);
		if (res<1) {
			WARN("Problem loading log_line from %s: %s\n", LOGFILE,strerror(errno));
			break;
		}
		res = (int)fread(&log_lines[i%MAXLOGSIZE].bl_item,sizeof(struct bl_item_t),1,fp);
		if (res<1) {
			WARN("Problem loading bl_item from %s: %s\n", LOGFILE,strerror(errno));
			break;
		}
		res = (int)fread(&log_lines[i%MAXLOGSIZE].raw,sizeof(struct conn_raw_t),1,fp);
		if (res<1) {
			WARN("Problem loading raw from %s: %s\n", LOGFILE,strerror(errno));
			break;
		}
	}
	if (i<log_size) {
		WARN("Read too few records from %s: expected %d, got %d\n",LOGFILE,log_size,i);
		log_size = i;
	}
	fclose(fp);*/
}

//--------------------------------------------------------
