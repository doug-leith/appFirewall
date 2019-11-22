
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
#include "dns_sniffer.h"

typedef struct conn_raw_t {
	int af; // network connection type: IPv4 or IPv6
	struct in6_addr src_addr, dst_addr; // local and remote addresses
	uint16_t sport, dport; // local and remote ports
	int udp;
	uint32_t seq, ack;
	struct timeval ts, start;
} conn_raw_t;

typedef struct conn_t {
	int pid; // PID of process associated with connection
	char name[MAXCOMLEN]; // Name of process associated with connection
	conn_raw_t raw;
	char domain[BUFSIZE]; // domain name of remote addr
	char src_addr_name[INET6_ADDRSTRLEN], dst_addr_name[INET6_ADDRSTRLEN];
} conn_t;

int get_pid_name(int pid, char* name);
int find_pid(conn_raw_t *c, char*name);
void cache_pid(int pid);
int is_ipv4_localhost(struct in6_addr* addr);
int is_ipv6_localhost(struct in6_addr* addr);
int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2);

int refresh_active_conns(int localhost);
conn_t* get_conn(int row);
void free_conn(conn_t* c);
int get_num_conns(void);
void init_pid_list(void);
char* pid_hash(const void *it);
int pid_cmp(const void* it1, const void* it2);
void dump_pidlist(list_t *l);
int find_fds(int pid, char* name, list_t* new_pid_list, list_t* new_gui_pid_list);

void start_pid_watcher(void);
void signal_pid_watcher(void);
void set_pid_watcher_hook(void (*hook)(void));
int get_pid_changed(void);
void clear_pid_changed(void);
#endif
