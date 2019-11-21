#ifndef sniffer_blocker
#define sniffer_blocker

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <pcap.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <string.h>
#include <pthread.h>
#include "util.h"
#include "pid_conn_info.h"
#include "log.h"
#include "blocklist.h"
#include "whitelist.h"
#include "hostlists.h"
#include "blocklists.h"
#include "dns_sniffer.h"
#include "libnet.h"
#include "circular_list.h"
#include "pid_conn_info.h"
#include "dtrace.h"

#define RST_PORT 2
#define PCAP_PORT 3

void init_sniffer_blocker(char* filter_exp);
void sniffer_blocker_callback(u_char *args, const struct pcap_pkthdr *pkthdr, 	const 			u_char* pkt);
void start_listener(void);
void stop_listener(void);
int listener_error(void);
int get_num_conns_blocked(void);
void set_num_conns_blocked(int val);
bl_item_t create_blockitem_from_addr(conn_raw_t *cr, int fast);

#endif
