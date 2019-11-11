
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

typedef struct conn_t {
	int pid; // PID of process associated with connection
	char name[MAXCOMLEN]; // Name of process associated with connection
	int af; // network connection type: IPv4 or IPv6
	struct in6_addr src_addr, dst_addr; // local and remote addresses
	int sport, dport; // local and remote ports
	char domain[BUFSIZE]; // domain name of remote addr
	char src_name[INET6_ADDRSTRLEN], dst_name[INET6_ADDRSTRLEN];
	char pid_name[BUFSIZE], conn_name[BUFSIZE], addr_name[BUFSIZE];
} conn_t;

typedef struct conn_info_t {
	char pid_name[BUFSIZE], conn_name[BUFSIZE], addr_name[BUFSIZE]; // formatted strings for GUI display
	int pid, af;
	char name[BUFSIZE]; // name of app associated with connections
	char domain[BUFSIZE]; // domain name
	struct in6_addr  addr; // the non-local address (we already know our own one!)
} conn_info_t;

typedef struct conn_raw_t {
	int af; // network connection type: IPv4 or IPv6
	struct in6_addr src_addr, dst_addr; // local and remote addresses
	int sport, dport;
} conn_raw_t;

int get_pid_name(int pid, char* name);
int find_pid(conn_raw_t *c, char*name, int udp);
int is_ipv4_localhost(struct in6_addr* addr);
int is_ipv6_localhost(struct in6_addr* addr);
int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2);

int refresh_active_conns(int localhost);
conn_info_t get_conns(int row);
int get_num_conns(void);

#endif
