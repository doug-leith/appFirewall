
#ifndef log_h
#define log_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include "util.h"
#include "blocklist.h"

// file for maintaining state over restarts
#define LOGFILE "log.dat"
#define LOGFILE_TXT "log.txt" // human readable log file
#define LOGSTRSIZE 256
#define MAXLOGSIZE 1024

typedef struct log_line_t {
	char *time_str, *log_line;
	struct bl_item_t bl_item;
	int blocked;
} log_line_t;

int get_log_size(void);
log_line_t get_log_item(int row);
void append_log(char* str, char* long_str, struct bl_item_t* bl_item, int blocked);
void save_log(void);
void load_log(void);
void clear_log(void);
int has_log_changed(void);
void clear_log_changed(void);

#endif /* log_h */
