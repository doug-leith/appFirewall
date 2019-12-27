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
#include "util.h"
#include "dtrace.h"

#define PCAP_PORT 3
#define MAX_INTS 5 // max number of interfaces to monitor
#define STR_SIZE 1024
#define PCAP_REFRESH_INTERVAL 5 // check if interfaces have changed

typedef struct sniffers_t {
	pcap_t *pds[MAX_INTS];  // pcap listener
	char* interfaces[MAX_INTS];
	//bpf_u_int32 mask[MAX_INTS], net[MAX_INTS];
	int needs_thread[MAX_INTS];
	pthread_t sniffer_threads[MAX_INTS];
	pthread_mutex_t sniffer_mutex;
	int num_pds;
	int is_sniffing;
} sniffers_t;
#define SNIFFERS_INITIALIZER {{NULL}, {NULL}, {0}, {0}, PTHREAD_ERRORCHECK_MUTEX_INITIALIZER, 0, 0}

int refresh_sniffers_list(sniffers_t* sn);
void sniffer_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char* pkt);
void free_sniffers(sniffers_t* sn);
void signal_interface_watcher(void);
void *listener(void *ptr);
void start_listener(void);
void close_sniffer_sock(void);

#endif /* pcap_sniffer_h */
