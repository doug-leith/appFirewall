//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef pid_conn_info
#define pid_conn_info

#include <stdio.h>
#include <stdlib.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "pthread.h"
#include "util.h"
#include "connection.h"
#include "dns_sniffer.h"
#include "is_blocked.h"
#include "log.h"
#include "dns_conn_cache.h"

// algorithm parameters
#define PID_CACHE_SIZE 3 // size of cache of recent PIDs and their names
# define PID_WATCHER_TIMEOUT 500 // in ms, after which we force refresh of active processes
#define REFRESH_TIMEOUT 0.05 // 50ms, after which we force full refresh in find_fds()
#define ESCAPEE_TIMEOUT 0.05 // 50ms, after which we check for escapees
#define STALE_ESCAPEE_TIMEOUT 10 // 10secs. for keeping stats on stale escapees
#define ESCAPEEMAX 10 // max num of escapees we try to catch concurrently
#define CATCHER_PORT 5 // port helper listens on for catching escapees

int get_pid_name(int pid, char* name);
int find_pid(conn_raw_t *c, char*name, int syn);
void cache_pid(int pid, char* name);

void init_pid_lists(void);
int find_fds(int pid, char* name, list_t* new_pid_list, int full_refresh);
int refresh_active_conns(int full_refresh);

void start_pid_watcher(void);
void signal_pid_watcher(int syn);
void set_pid_watcher_hook(void (*hook)(void));
int get_pid_changed(void);
void clear_pid_changed(void);
void find_escapees(void);
void *catch_escapee(void *ptr);

//swift
conn_t get_gui_conn(int_sw row);
void free_conn(conn_t* c);
int_sw get_num_gui_conns(void);
void print_escapees(void);
void update_gui_pid_list(void);

#endif
