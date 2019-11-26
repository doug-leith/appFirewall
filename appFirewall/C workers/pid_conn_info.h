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

int get_pid_name(int pid, char* name);
int find_pid(conn_raw_t *c, char*name);
void cache_pid(int pid, char* name);

void init_pid_lists(void);
int find_fds(int pid, char* name, Hashtable* old_pid_list_fdtab, list_t* new_pid_list, Hashtable* new_pid_list_fdtab, list_t* new_gui_pid_list);
int refresh_active_conns(int localhost);

void start_pid_watcher(void);
void signal_pid_watcher(void);
void set_pid_watcher_hook(void (*hook)(void));
int get_pid_changed(void);
void clear_pid_changed(void);
void *catch_escapee(void *ptr);

//swift
conn_t get_conn(int_sw row);
void free_conn(conn_t* c);
int_sw get_num_conns(void);
void print_escapees(void);

#endif
