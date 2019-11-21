//
//  pcap_sniffer.h
//  com.leith.appFirewall-Helper
//
//  Created by Doug Leith on 13/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

#ifndef pcap_sniffer_h
#define pcap_sniffer_h

#include <stdio.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>
#include "util.h"

#define PCAP_PORT 3

void start_sniffer(char* filter_exp);
void sniffer_callback(u_char* args, const struct pcap_pkthdr *pkthdr, const u_char* pkt);
void *listener(void *ptr);
void stop_listener(void);
void start_listener(void);
void close_sniffer_sock(void);

#endif /* pcap_sniffer_h */
