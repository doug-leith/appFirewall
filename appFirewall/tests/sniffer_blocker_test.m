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
	
	// check final packet processing (once have matched conn to pid)
	// won't be flagged as blocked, connection will just be logged
	set_path("/tmp/");
	load_log("empty", "txt_log");
	double confidence = 0.5; int r_sock=-1;
	process_conn(&c, &b, confidence, &r_sock, 0);
	XCTAssertEqual(get_log_size(),1);
	log_line_t *l= get_log_row(0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,"<not found> → testdomain:257"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,b.name),0);
	XCTAssertEqual(l->raw.sport,c.sport);
	XCTAssertEqual(l->blocked,0);
	XCTAssertEqual(l->confidence, 0.5);
	// checking processing of blocked conn requires connection to helper,
	// so skip it here

	//void process_conn_waiting_list(void)

	/*void handle_tcp_conn(conn_raw_t *cr, int pkt_pid, char* pkt_name, int syn, int synack);
	void handle_udp_conn(conn_raw_t *cr, int pkt_pid, char* pkt_name);
	void process_conn(conn_raw_t *cr, bl_item_t *c, double confidence, int *r_sock, int logstats);
	int in_udp_cache(conn_raw_t *cr);
	void add_to_udp_cache(conn_raw_t *cr);*/

}

@end
