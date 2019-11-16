
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
#include "util.h"
#include "dns_sniffer.h"

typedef struct conn_raw_t {
	int af; // network connection type: IPv4 or IPv6
	struct in6_addr src_addr, dst_addr; // local and remote addresses
	int sport, dport; // local and remote ports
	int udp;
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
int is_ipv4_localhost(struct in6_addr* addr);
int is_ipv6_localhost(struct in6_addr* addr);
int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2);

int refresh_active_conns(int localhost);
conn_t* get_conns(int row);
int get_num_conns(void);
void init_pid_list(void);

#endif
