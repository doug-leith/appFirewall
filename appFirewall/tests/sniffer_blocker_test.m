//
//  sniffer_blocker_test.m
//  appFirewallTests
//
//  Created by Doug Leith on 01/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>

@interface sniffer_blocker_test : XCTestCase

@end

#include "sniffer_blocker.h"
#include "dns_sniffer.h"
#include "conn_list.h"

@implementation sniffer_blocker_test

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testSnifferBlocker {
	set_num_conns_blocked(1);
	XCTAssertEqual(get_num_conns_blocked(),1);
	set_num_conns_blocked(2);
	XCTAssertEqual(get_num_conns_blocked(),2);
	
	// flush dns cache
	load_dns_cache("empty"); // will clear cache
	// clear blacklists
	load_connlist(get_blocklist(),"empty");
	load_connlist(get_whitelist(),"empty");

	// basic type conversion
	conn_raw_t c; memset(&c,1,sizeof(c));
	c.af = AF_INET;
	char s[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET,&c.dst_addr,s,INET6_ADDRSTRLEN);
	c.sport = 100;
	int pkt_pid = 100;
	char* pkt_name = "test";
	bl_item_t b = create_blockitem_from_addr(&c, 0, pkt_pid, pkt_name);
	XCTAssertEqual(strcmp(b.name,pkt_name),0);
	XCTAssertEqual(strcmp(b.domain,s),0);
	XCTAssertEqual(strcmp(b.addr_name,s),0);
	
	// lookup of domain name
	set_path("/tmp/");
	load_dns_cache("empty");
	append_dns(AF_INET, c.dst_addr, "testdomain");
	b = create_blockitem_from_addr(&c, 0, pkt_pid, pkt_name);
	XCTAssertEqual(strcmp(b.name,pkt_name),0);
	XCTAssertEqual(strcmp(b.domain,"testdomain"),0);
	XCTAssertEqual(strcmp(b.addr_name,s),0);

	// lookup of app name (which will fail as no running process)
	b = create_blockitem_from_addr(&c, 0, pkt_pid, NULL);
	XCTAssertEqual(strcmp(b.name,NOTFOUND),0);
	XCTAssertEqual(strcmp(b.domain,"testdomain"),0);
	XCTAssertEqual(strcmp(b.addr_name,s),0);
	
	// check UDP pkt processing for uncached pkt
	set_path("/tmp/");
	load_log("empty", "txt_log");
	clear_udp_cache();
	handle_udp_conn(&c, pkt_pid, pkt_name);
	XCTAssertEqual(get_log_size(),1);
	log_line_t *l= get_log_row(0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,"test → UDP testdomain:257"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,pkt_name),0);
	XCTAssertEqual(l->raw.sport,c.sport);
	XCTAssertEqual(l->blocked,0);
	XCTAssertEqual(l->confidence, 1.0);

	// check UDP cache operation
	clear_udp_cache();
	XCTAssertEqual(in_udp_cache(&c),0);
	add_to_udp_cache(&c);
	XCTAssertEqual(in_udp_cache(&c),1);
	
	// check UDP pkt processing for cached pkt
	handle_udp_conn(&c, pkt_pid, pkt_name);
	XCTAssertEqual(get_log_size(),1);
	
	// check QUIC NOTFOUND processing
	clear_udp_cache(); 	load_log("empty", "txt_log");
	handle_udp_conn(&c, pkt_pid, NULL);
	XCTAssertEqual(get_log_size(),1);
	l= get_log_row(0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,"<not found> → UDP testdomain:257"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,b.name),0);
	XCTAssertEqual(l->raw.sport,c.sport);
	XCTAssertEqual(l->blocked,0);
	XCTAssertEqual(l->confidence, 1.0);

	clear_udp_cache(); 	load_log("empty", "txt_log");
	c.dport = 443;
	handle_udp_conn(&c, pkt_pid, NULL);
	XCTAssertEqual(get_log_size(),1);
	l= get_log_row(0);
	XCTAssertNotEqual(l,NULL);
	//printf("#3 %s %s\n",l->log_line,l->bl_item.name);
	XCTAssertEqual(strcmp(l->log_line,"Google Chrome H → UDP/QUIC testdomain:443"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,"Google Chrome H"),0);
	XCTAssertEqual(l->raw.sport,c.sport);
	XCTAssertEqual(l->blocked,0);
	XCTAssertEqual(l->confidence, 1.0);
	c.dport = 257;

	// check UDP pkt processing for localhost
	conn_raw_t c_local; memset(&c_local,0,sizeof(c_local));
	c_local.af = AF_INET;
	XCTAssertEqual(get_log_size(),1);
	XCTAssertEqual(robust_inet_pton(&c_local.af, "127.0.0.1", &c_local.src_addr),1);
	XCTAssertEqual(robust_inet_pton(&c_local.af, "8.8.8.8", &c_local.dst_addr),1);
	handle_udp_conn(&c_local, pkt_pid, pkt_name);
	XCTAssertEqual(get_log_size(),1);
	XCTAssertEqual(robust_inet_pton(&c_local.af, "127.0.0.1", &c_local.dst_addr),1);
	XCTAssertEqual(robust_inet_pton(&c_local.af, "8.8.8.8", &c_local.src_addr),1);
	handle_udp_conn(&c_local, pkt_pid, pkt_name);
	XCTAssertEqual(get_log_size(),2);
	c_local.af = AF_INET6;
	XCTAssertEqual(robust_inet_pton(&c_local.af, "::1", &c_local.src_addr),1);
	handle_udp_conn(&c_local, pkt_pid, pkt_name);
	XCTAssertEqual(get_log_size(),2);

	// check TCP pkt processing
	// check final packet processing (once have matched conn to pid)
	// won't be flagged as blocked, connection will just be logged
	set_path("/tmp/");
	load_log("empty", "txt_log");
	double confidence = 0.5; int r_sock=-1;
	process_conn(&c, &b, confidence, &r_sock, 0);
	XCTAssertEqual(get_log_size(),1);
	l= get_log_row(0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,"<not found> → testdomain:257"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,b.name),0);
	XCTAssertEqual(l->raw.sport,c.sport);
	XCTAssertEqual(l->blocked,0);
	XCTAssertEqual(l->confidence, 0.5);
	// checking processing of blocked conn requires connection to helper
	// to send TCP RST, so skip it.

	// TCP syn-ack with known process name
	int syn=0, synack=1;
	set_path("/tmp/");
	load_log("empty", "txt_log");
	handle_tcp_conn(&c, pkt_pid, pkt_name, syn, synack);
	XCTAssertEqual(get_waiting_list_size(),0);
	XCTAssertEqual(get_log_size(),1);
	l= get_log_row(0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,"test → testdomain:257"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,pkt_name),0);
	XCTAssertEqual(l->raw.sport,c.sport);
	XCTAssertEqual(l->blocked,0);
	XCTAssertEqual(l->confidence, 1.0);

	// TCP syn-ack with unknown process name
	set_path("/tmp/");
	load_log("empty", "txt_log");
	init_waiting_list();
	load_dns_cache("empty"); // will clear cache
	handle_tcp_conn(&c, pkt_pid, NOTFOUND, 0, 1);
	XCTAssertEqual(get_log_size(),0);
	XCTAssertEqual(get_waiting_list_size(),1);

	// TCP SYN
	set_path("/tmp/");
	load_log("empty", "txt_log");
	handle_tcp_conn(&c, pkt_pid, pkt_name, 1, 0);
	XCTAssertEqual(get_log_size(),0);
	XCTAssertEqual(get_waiting_list_size(),1);

	// TCP neither SYN not SYNACK
	handle_tcp_conn(&c, pkt_pid, pkt_name, 0, 0);
	XCTAssertEqual(get_log_size(),0);
	XCTAssertEqual(get_waiting_list_size(),1);

	// check waiting list processing
	clear_waiting_list();
	set_path("/tmp/");
	load_log("empty", "txt_log");
	XCTAssertEqual(get_waiting_list_size(),0);
	// waiting list empty
	process_conn_waiting_list();
	// waiting list NOTFOUND and no timeout
	gettimeofday(&c.ts, NULL);
	add_waiting_list(&c);
	XCTAssertEqual(get_waiting_list_size(),1);
	process_conn_waiting_list();
	XCTAssertEqual(get_log_size(),0);
	// waiting list NOTFOUND and timeout
	gettimeofday(&c.ts, NULL);
	c.ts.tv_sec -= (WAIT_TIMEOUT+1);
	clear_waiting_list();
	add_waiting_list(&c);
	process_conn_waiting_list();
	XCTAssertEqual(get_waiting_list_size(),0);
	XCTAssertEqual(get_log_size(),1);
	// to do: check case where pid is found in pid_info
}

- (void)testSnifferBlockerPktParsing {
	u_char pkt[1024]; memset(pkt,0,1024);
	
	// check stepping past IPv4 header
	pkt[0] = 0x40;
	struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)pkt;
	ip->ip_hl = 1;
	XCTAssertNotEqual(payload(pkt),NULL);
	XCTAssertEqual(payload(pkt),((u_char *)ip + (ip->ip_hl * 4)));
	
	// check stepping past IPv6 header
	pkt[0] = 0x60;
	XCTAssertNotEqual(payload(pkt),NULL);
	XCTAssertEqual(payload(pkt),pkt+sizeof(struct libnet_ipv6_hdr));
	
	// IPv4 pkt header processing
	int syn, synack;
	pkt[0] = 0x40;
	ip = (struct libnet_ipv4_hdr *)pkt;
	ip->ip_hl = 1;
	memset(&ip->ip_src,1,sizeof(ip->ip_src));
	memset(&ip->ip_dst,2,sizeof(ip->ip_dst));
	// UDP
	ip->ip_p = IPPROTO_UDP;
	struct libnet_udp_hdr *udp = (struct libnet_udp_hdr *)payload(pkt);
	uint16_t sport = 3, dport = 4;
	udp->uh_sport = htons(sport);
	udp->uh_dport = htons(dport);
	conn_raw_t c = get_conn_from_pkt(pkt, &syn, &synack);
	XCTAssertEqual(syn,0);
	XCTAssertEqual(synack,0);
	XCTAssertEqual(c.udp,1);
	XCTAssertEqual(c.af,AF_INET);
	XCTAssertEqual(c.sport,dport);
	XCTAssertEqual(c.dport,sport);
	XCTAssertEqual(memcmp(&c.src_addr,&ip->ip_dst,sizeof(ip->ip_dst)),0);
	XCTAssertEqual(memcmp(&c.dst_addr,&ip->ip_src,sizeof(ip->ip_src)),0);
	//TCP/IPv6
	pkt[0] = 0x60;
	struct libnet_ipv6_hdr *ip6 = (struct libnet_ipv6_hdr *)pkt;
	memset(&ip6->ip_src,1,16);
	memset(&ip6->ip_dst,2,16);
	ip6->ip_nh = IPPROTO_TCP;
	struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)payload(pkt);
	// SYNACK
	tcp->th_flags=TH_SYN | TH_ACK;
	tcp->th_sport = htons(sport); tcp->th_dport = htons(dport);
	uint32_t seq=1, ack=100;
	tcp->th_seq = htonl(seq); tcp->th_ack = htonl(ack);
	c = get_conn_from_pkt(pkt, &syn, &synack);
	XCTAssertEqual(syn,0);
	XCTAssertEqual(synack,1);
	XCTAssertEqual(c.udp,0);
	XCTAssertEqual(c.af,AF_INET6);
	XCTAssertEqual(c.sport,dport);
	XCTAssertEqual(c.dport,sport);
	XCTAssertEqual(memcmp(&c.src_addr,&ip6->ip_dst,sizeof(ip6->ip_dst)),0);
	XCTAssertEqual(memcmp(&c.dst_addr,&ip6->ip_src,sizeof(ip6->ip_src)),0);
	XCTAssertEqual(c.ack,seq+1);
	XCTAssertEqual(c.seq,ack);
	// SYN
	tcp->th_flags=TH_SYN ;
	c = get_conn_from_pkt(pkt, &syn, &synack);
	XCTAssertEqual(syn,1);
	XCTAssertEqual(synack,0);
	// not syn nor synack
	tcp->th_flags=0 ;
	c = get_conn_from_pkt(pkt, &syn, &synack);
	XCTAssertEqual(syn,0);
	XCTAssertEqual(synack,0);

	// neither TCP nor UDP
	ip6->ip_nh = 0;
	c = get_conn_from_pkt(pkt, &syn, &synack);
	XCTAssertEqual(c.udp,-1);
	}

@end
