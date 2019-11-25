
#ifndef log_h
#define log_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <string.h>
#include "util.h"
//#include "blocklist.h"
#include "is_blocked.h"
#include "circular_list.h"

// file for maintaining state over restarts
#define LOGFILE "log.dat"
#define LOGFILE_TXT "log.txt" // human readable log file
#define LOGSTRSIZE 256
#define MAXLOGSIZE 1024

typedef struct log_line_t {
	char time_str[LOGSTRSIZE], log_line[LOGSTRSIZE];
	struct bl_item_t bl_item;
	int blocked;
	conn_raw_t raw;
} log_line_t;

int get_log_size(void);
log_line_t* get_log_row(int row);
log_line_t* find_log_by_conn(char* name, conn_raw_t* c, int debug);
void get_log_addr_name(int row, char* str, int len);
void append_log(char* str, char* long_str, struct bl_item_t* bl_item, conn_raw_t *raw, int blocked);
void save_log(void);
void load_log(void);
void clear_log(void);
int has_log_changed(void);
void clear_log_changed(void);

void filter_log_list(int show_blocked, const char* str);
int get_filter_log_size(void);
log_line_t* get_filter_log_row(int row);
void get_filter_log_addr_name(int row, char* str, int len);

#endif /* log_h */
