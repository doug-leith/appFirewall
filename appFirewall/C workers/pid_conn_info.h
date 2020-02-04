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
#define PID_CACHE_SIZE 3 // size of cache of recent PIDs and their names.
#define PID_WATCHER_TIMEOUT 1000 // in ms, after which we force refresh of list of active processes and their connections.  GUI refreshes every 1s.
#define REFRESH_TIMEOUT 0.1 // in secs, after which we force full refresh in find_fds() (so correcting any errors caused by reused of file descriptors).  since reuse is rare, we could make this timeout longer ?
#define REFRESH_THRESH 0.05 // in secs, if more than 5% of fd's are observed to be incorrect due to file descriptor reuse then we fall back to always doing a full refresh in find_fds().
#define ESCAPEE_TIMEOUT 0.05 // in secs, after which we check for escapees.  we leave a delay so as to give time to kill connections via sending TCP RSTs on SYN-ACK before invoking escapee catcher process (which is relatively slow/expensive).
#define STALE_ESCAPEE_TIMEOUT 10 // 10secs. for keeping stats on stale escapees
#define ESCAPEEMAX 1 // max num of escapees we try to catch concurrently
#define MAX_ESCAPEE_ATTEMPTS 3 // max number of times we call catcher for same connection
#define CATCHER_PORT 5 // port helper listens on for catching escapees

typedef struct last_pid_item_t {
	int pid;
	char name[MAXCOMLEN];
} last_pid_item_t;

typedef struct pid_path_name_t {
	char name[MAXCOMLEN]; // process name
	char path[PROC_PIDPATHINFO_MAXSIZE+1];  // path to executable
} pid_path_name_t;

typedef struct pid_info_t {
	list_t pid_list; // list of active pid's and network conns
  list_t gui_pid_list; // filtered list for GUI
  list_t last_pid_list; // cache of recent PIDs and their names
  list_t pid_path_list; // list of process names and paths to their executables
	int changed; // flag to GUI if pid list has changed
	list_t escapee_list; // list of blocked yet active connections
	int escapee_thread_count;
	// pointers to pid_info syscalls, so can be replaced by stubs for testing
	int (*proc_pidinfo)(int pid, int flavor, uint64_t arg, void *buffer, int buffersize);
	int (*proc_pidfdinfo)(int pid, int fd, int flavor, void * buffer, int buffersize);
	int (*proc_listpids)(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize);
	void (*start_catch_escapee)(conn_t *e);
	int (*is_ppp)(int af, struct in6_addr *src_addr, struct in6_addr *dst_addr);
} pid_info_t;
#define PID_INFO_INITIALSER {LIST_INITIALISER,LIST_INITIALISER,LIST_INITIALISER,LIST_INITIALISER,1,LIST_INITIALISER,0,&proc_pidinfo,&proc_pidfdinfo,&proc_listpids,&start_catch_escapee,&is_ppp}

pid_info_t* get_pid_info(void);
int get_pid_name(int pid, char* name, uint32_t *status);
int get_pid_path(int pid, char* path, int size);
char* get_name_path(char* name);
int find_pid(conn_raw_t *c, char*name, int syn);
void cache_pid(int pid, char* name);
conn_t * find_conn(int pid, int fd);

void init_pid_lists(void);
int find_fds(int pid, char* name, list_t* new_pid_list, int full_refresh);
int refresh_active_conns(int full_refresh);

void start_pid_watcher(void);
void signal_pid_watcher(int force, int full_refresh);
void set_pid_watcher_hook(void (*hook)(void));
int get_pid_changed(void);
void clear_pid_changed(void);
void find_escapees(void);
void start_catch_escapee(conn_t *e);
void *catch_escapee(void *ptr);

//swift
conn_t get_gui_conn(int_sw row);
void free_conn(conn_t* c);
int_sw get_num_gui_conns(void);
void print_escapees(void);
void update_gui_pid_list(void);

#endif
