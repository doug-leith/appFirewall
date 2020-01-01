//
//  pcap_sniffer.h
//  com.leith.appFirewall-Helper
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef pcap_sniffer_h
#define pcap_sniffer_h

#include <stdio.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <sys/select.h>
#include "util.h"
#include "dtrace.h"

#define PCAP_PORT 3
#define MAX_INTS 5 // max number of interfaces to monitor
#define STR_SIZE 1024
#define SNIFFER_LOOP_TIMEOUT 1 // 1 sec

typedef struct sniffers_t {
	pcap_t *pds[MAX_INTS];  // pcap listener
	char interfaces[MAX_INTS][STR_SIZE];
	int fd[MAX_INTS];
	int datalink[MAX_INTS];
	int offset[MAX_INTS];
	int num_pds;
} sniffers_t;

typedef struct sniffer_callback_args_t {
	sniffers_t *sn;
	int i;
} sniffer_callback_args_t;

int refresh_sniffers_list(sniffers_t* sn, char* filter_exp);
int get_interfaces(char intf[MAX_INTS][STR_SIZE]);
void sniffer_loop(pcap_handler callback, int *running, char* tag, char* filter_exp);
void sniffer_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char* pkt);
void *listener(void *ptr);
void start_listener(void);
void close_sniffer_sock(void);

#endif /* pcap_sniffer_h */
