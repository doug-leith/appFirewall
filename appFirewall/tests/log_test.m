//
//  log_test.m
//  appFirewallTests
//
//  Created by Doug Leith on 01/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>

@interface log_test : XCTestCase

@end

#include "../C workers/log.h"

@implementation log_test

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testLog {

	set_path("/tmp/");
	load_log("empty", "txt_log");
	XCTAssertEqual(has_log_changed(),2);
	
	// add an item
	char *str="str", *long_str="longstr";
	bl_item_t b; strcpy(b.name,"testname"); strcpy(b.domain,"testdomain");
	strcpy(b.addr_name,"addr");
	conn_raw_t c; memset(&c,3,sizeof(conn_raw_t)); c.af=AF_INET; c.sport = 3;
	int blocked = 2; double confidence = 0.876;
	append_log(str, long_str, &b, &c, blocked, confidence);
	XCTAssertEqual(get_log_size(),1);
	XCTAssertEqual(has_log_changed(),1);
	clear_log_changed();
	XCTAssertEqual(has_log_changed(),0);
	log_line_t *l= get_log_row(0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,str),0);
	XCTAssertEqual(strcmp(l->bl_item.name,b.name),0);
	XCTAssertEqual(l->raw.sport,c.sport);
	XCTAssertEqual(l->blocked,blocked);
	XCTAssertEqual(l->confidence, confidence);
	
	// save and reload
	save_log("log");
	XCTAssertEqual(get_log_size(),1);
	clear_log();
	XCTAssertEqual(get_log_size(),0);
	XCTAssertEqual(has_log_changed(),2);
	clear_log_changed();
	load_log("log", "txt_log");
	XCTAssertEqual(get_log_size(),1);
	XCTAssertEqual(has_log_changed(),2);
	clear_log_changed();
	
	// add second item and retrieve first
	bl_item_t b2; strcpy(b2.name,"testname2"); strcpy(b2.domain,"domain2");
	strcpy(b2.addr_name,"addr2");
	conn_raw_t c2; memset(&c2,1,sizeof(conn_raw_t)); c2.af=AF_INET6;  c2.sport = 100;
	append_log("str2", "longstr2", &b2, &c2, 1, 0.54);
	XCTAssertEqual(get_log_size(),2);
	XCTAssertEqual(has_log_changed(),1);
	l=find_log_by_conn("doesnt_exist", &c, 0);
	XCTAssertEqual(l,NULL);
	l=find_log_by_conn(b.name, &c, 0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,"str"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,b.name),0);
	XCTAssertEqual(l->raw.sport,c.sport);
	XCTAssertEqual(l->blocked,blocked);
	XCTAssertEqual(l->confidence, confidence);

	// update entry
	XCTAssertEqual(update_log_by_conn(b.name, &c, 1), confidence);
	l=find_log_by_conn(b.name, &c, 0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,"str"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,b.name),0);
	XCTAssertEqual(l->raw.sport,c.sport);
	XCTAssertEqual(l->blocked,blocked);
	XCTAssertEqual(l->confidence, 1.0);
	// update with different name
	XCTAssertEqual(update_log_by_conn("newname", &c2, 1), 0.54);
	l=find_log_by_conn("newname", &c2, 0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,"str2"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,"newname"),0);
	XCTAssertEqual(l->raw.sport,c2.sport);
	// now that entry has high confidence, try to change name again
	XCTAssertEqual(update_log_by_conn("newname2", &c2, 1), -1);

	// check sniffer_blocker API for adding to log
	bl_item_t b3; strcpy(b3.name,"testname3"); strcpy(b3.domain,"testdomain3");
	strcpy(b3.addr_name,"addr3");
	conn_raw_t c3; memset(&c3,0,sizeof(conn_raw_t)); c3.af=AF_INET;  c3.dport = 5000;
	log_connection(&c3, &b3, 1, 0.33, "?");
	l=find_log_by_conn("testname3", &c3, 0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->log_line,"testname3? → testdomain3:5000"),0);
	XCTAssertEqual(strcmp(l->bl_item.name,"testname3"),0);
	XCTAssertEqual(l->raw.sport,c3.sport);

	// domain search
	XCTAssertEqual(search_log_domains("notthere"),0);
	XCTAssertEqual(search_log_domains("test"),2);
	XCTAssertEqual(strcmp(get_suggestion(0),"testdomain"),0);
	XCTAssertEqual(strcmp(get_suggestion(1),"testdomain3"),0);

	// filtering
	filter_log_list(0, NULL);
	XCTAssertEqual(get_filter_log_size(),0);
	filter_log_list(1, NULL);
	XCTAssertEqual(strcmp(get_filter_log_addr_name(0),"101:101:101:101:101:101:101:101"),0);
	XCTAssertEqual(strcmp(get_filter_log_addr_name(1),"0.0.0.0"),0);
	XCTAssertEqual(get_filter_log_size(),2);
	filter_log_list(2, NULL);
	XCTAssertEqual(get_filter_log_size(),3);
	XCTAssertEqual(strcmp(get_filter_log_addr_name(0),"3.3.3.3"),0);
	XCTAssertEqual(strcmp(get_filter_log_addr_name(1),"101:101:101:101:101:101:101:101"),0);

	l = get_filter_log_row(0);
	XCTAssertNotEqual(l,NULL);
	XCTAssertEqual(strcmp(l->bl_item.name,"testname"),0);
	XCTAssertEqual(l->raw.sport,3);
	
	// just check that these run at all
	open_logtxt("txt_log");
	close_logtxt();
	reopen_logtxt();
	close_logtxt();
	}

- (void)testUtils {
	set_path("www");
	XCTAssertEqual(strcmp(get_path(),"www"),0);
	set_error_msg("test error",0);
	XCTAssertEqual(strcmp(get_error_msg(),"test error"),0);
	XCTAssertEqual(get_error_force(),0);
	set_error_msg("test error",1);
	XCTAssertEqual(get_error_force(),1);
	char test[1024]; strcpy(test,"  123 4 ");
	XCTAssertEqual(strcmp(trimwhitespace(test),"123 4"),0);
	struct in6_addr a;
	memset(&a,0,sizeof(a)); XCTAssertEqual(is_ipv4_localhost(&a),1);
	uint8_t *aa = (uint8_t *)&a; aa[0]=1; aa[3]=127;
	memset(&a,0,sizeof(a)); XCTAssertEqual(is_ipv4_localhost(&a),1);
	memset(&a,1,sizeof(a)); XCTAssertEqual(is_ipv4_localhost(&a),0);
	memset(&a,0,sizeof(a)); XCTAssertEqual(is_ipv6_localhost(&a),0);
	a=in6addr_loopback; XCTAssertEqual(is_ipv6_localhost(&a),1);
	memset(&a,1,sizeof(a)); XCTAssertEqual(is_ipv6_localhost(&a),0);
	struct in6_addr a2;
	memcpy(&a2,&a,sizeof(a2));
	XCTAssertEqual(are_addr_same(AF_INET,&a,&a2),1);
	XCTAssertEqual(are_addr_same(AF_INET6,&a,&a2),1);
	memset(&a2,0,sizeof(a2));
	XCTAssertEqual(are_addr_same(AF_INET,&a,&a2),0);
	XCTAssertEqual(are_addr_same(AF_INET6,&a,&a2),0);
	char s[INET6_ADDRSTRLEN];
	int af = AF_INET;
	XCTAssertEqual(robust_inet_pton(&af, "8.8.8.8", &a),1);
	XCTAssertEqual(af,AF_INET);
	XCTAssertEqual(robust_inet_pton(&af, "::1", &a),1);
	XCTAssertEqual(af,AF_INET6);
	af = AF_INET;
	robust_inet_ntop(&af, &a, s, INET6_ADDRSTRLEN);
	XCTAssertEqual(af,AF_INET);
	}
	

@end
