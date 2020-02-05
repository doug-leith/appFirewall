//
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

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
#include "dns_sniffer.h"
#include "libnet.h"
#include "circular_list.h"
#include "connection.h"
#include "dtrace.h"
#include "is_blocked.h"
#include "dns_conn_cache.h"

#define RST_PORT 2 // port help listens for instructions to send TCP RSTs
#define PCAP_PORT 3 // port helper sends sniffed pkt info on

#define SNAPLEN 1500 // needs to be big enough to capture dns payload

// algorithm parameters
#define WAIT_TIMEOUT 0.02 // 20ms timeout after which we either guess the process associated with a new SYN-ACK or declare the process NOTFOUND.  in latter case, if a long-enough lived connection that should be blocked then it will become an escapee and be caught and blocked.  if connection is v short then we can leak packets here -- either by TCP RSTs failing since pkt seq numbers have advanced or by escapee catcher being too slow, so we'd like to keep this timeout short e.g. might reduce it to 10ms
#define SYN_TIMEOUT 1 // SYN packets >1s old are dropped (likely due to wakeup after sleep).  could probably safely make this smaller
#define CONF_THRESH 0.5 // when confidence in guess of process associated with a connection is less than this then we add a ? next to name in log and disable connection blocking.  decreasing this makes blocking more aggressive.
#define UDP_CACHE_LIFETIME 3600 // UDP connections expire after 3600 secs (1 hour)

void init_sniffer_blocker(char* filter_exp);
bl_item_t create_blockitem_from_addr(conn_raw_t *cr, int syn, int pkt_pid, char* pkt_name);
void handle_tcp_conn(conn_raw_t *cr, int pkt_pid, char* pkt_name, int syn, int synack);
void handle_udp_conn(conn_raw_t *cr, int pkt_pid, char* pkt_name);
void process_conn(conn_raw_t *cr, bl_item_t *c, double confidence, int *r_sock, int logstats);
void process_conn_waiting_list(void);
int in_udp_cache(conn_raw_t *cr);
void clear_udp_cache(void);
void add_to_udp_cache(conn_raw_t *cr);
size_t get_waiting_list_size(void);
void init_waiting_list(void);
void clear_waiting_list(void);
void add_waiting_list(conn_raw_t *cr);

u_char* payload(u_char* pkt);
conn_raw_t get_conn_from_pkt(u_char* pkt, int* syn, int* synack);

// swift
void start_listener(void);
void stop_listener(void);
int_sw get_num_conns_blocked(void);
void set_num_conns_blocked(int_sw val);
int sniffer_blocker_error(void);
int check_for_error(void);

#endif
