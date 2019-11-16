#include "log.h"

// circular list
static log_line_t log_lines[MAXLOGSIZE] = {0};
static int log_size=0;
static int log_start=0;
FILE *fp_txt = NULL; // pointer to human readable log file
int changed = 0; // flag to record whether log has been updated
#define STR_SIZE 1024

int has_log_changed(void) {
	return changed;
}

void clear_log_changed(void) {
	changed = 0;
}

int get_log_size(void) {
	return log_size;
}

log_line_t get_log_item(int row) {
	return log_lines[(row+log_start)%MAXLOGSIZE];
}

void get_log_addr_name(int row, char* str, int len) {
	log_line_t *l = &log_lines[(row+log_start)%MAXLOGSIZE];
	inet_ntop(l->raw.af,&l->raw.dst_addr,str,len);
	//printf("get_log_addr_name '%s'\n",str);
}

void append_log(char* str, char* long_str, struct bl_item_t* bl_item, conn_raw_t *raw, int blocked) {
	changed = 1; // record for GUI fact that log has been updated
	if (log_size == MAXLOGSIZE) {
		free(log_lines[log_start%MAXLOGSIZE].log_line);
		free(log_lines[log_start%MAXLOGSIZE].time_str);
		log_start++;
		log_size--;
	}
	//printf("append_log(): %d\n",(int)strlen(str));
	int end = (log_start+log_size)%MAXLOGSIZE;
	int len = (int)strlen(str)+1;
	if (len > STR_SIZE) len = STR_SIZE;
	log_lines[end].log_line = calloc(1,len);
	strlcpy(log_lines[end].log_line,str,len);
	time_t t;
	time(&t);
	str=asctime(localtime(&t));
	str[strlen(str)-1]=0; // remove "\n"
	len = (int)strlen(str)+1;
	if (len > STR_SIZE) len = STR_SIZE;
	log_lines[end].time_str = calloc(1,len);
	strlcpy(log_lines[end].time_str, str, len);
	memcpy(&log_lines[end].bl_item,bl_item,sizeof(struct bl_item_t));
	memcpy(&log_lines[end].raw,raw,sizeof(conn_raw_t));
	log_lines[end].blocked = blocked;
	log_size++;
	
	// and update human-readable log file
	if (fp_txt) {
		fprintf(fp_txt,"%s\t%s\n", log_lines[end].time_str, long_str);
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
	int i;
	for(i = log_start; i < log_start+log_size; i++){
		free(log_lines[i%MAXLOGSIZE].time_str);
		free(log_lines[i%MAXLOGSIZE].log_line);
	}
	log_start=0; log_size=0;
}

void save_log(void) {
	//printf("saving log\n");
	fflush(fp_txt); // flush text log
	
	char path[STR_SIZE]; strlcpy(path,get_path(),STR_SIZE);
	strlcat(path,LOGFILE,STR_SIZE);
	FILE *fp = fopen (path,"w+");
	if (fp==NULL) {
		WARN("Problem opening %s for writing: %s\n", LOGFILE, strerror(errno));
		return;
	}
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
}

void load_log() {
	//printf("loading log\n");
	//return;
	//printf("log: %s\n",strcat(get_path(),LOGFILE));

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
	fclose(fp);
}

//--------------------------------------------------------
