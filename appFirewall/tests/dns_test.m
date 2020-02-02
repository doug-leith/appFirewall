//
//  dns_test.m
//  appFirewallTests
//
//  Created by Doug Leith on 01/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>

@interface dns_test : XCTestCase

@end

#include "../C workers/util.h"
#include "../C workers/dns_conn_cache.h"
#include "../C workers/dns_sniffer.h"

@implementation dns_test

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testDNSSniffer {
	set_path("/tmp/");
	load_dns_cache("empty");
	// check save and fetch
	struct in6_addr a, b;
	inet_pton(AF_INET,"8.8.8.8",&a);
	inet_pton(AF_INET,"9.9.9.9",&b);
	XCTAssertEqual(lookup_dns_name(AF_INET, a),NULL);
	append_dns(AF_INET, a, "test");
	XCTAssertEqual(strcmp(lookup_dns_name(AF_INET, a),"test"),0);
	XCTAssertEqual(lookup_dns_name(AF_INET, b),NULL);
	
	// check save and reload
	save_dns_cache("dns");
	load_dns_cache("empty"); // will clear cache
	XCTAssertEqual(lookup_dns_name(AF_INET, a),NULL);
	load_dns_cache("dns");
	char* res = lookup_dns_name(AF_INET, a);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res,"test"),0);
	
	// test recall of count info
	char *c = get_dns_count_str(AF_INET, a);
	XCTAssertEqual(strcmp(c,"test(1) "),0);
	c = get_dns_count_str(AF_INET, b);
	XCTAssertEqual(strlen(c),0);
	append_dns(AF_INET, a, "test2");
	c = get_dns_count_str(AF_INET, a);
	printf("%s\n",c);
	XCTAssertEqual(strcmp(c,"test(1) test2(1) "),0);

	/*
	// TO DO.  test dns packet parser
	int dns_sniffer(const u_char* pkt, size_t pkt_len);
	*/
}

- (void)testDNSCache {
	// test saving to cache and fetching results
	XCTAssertEqual(load_dns_conn_list("/tmp/", "empty"),-1);
	add_dns_conn("testdomain", "test");
	double confidence;
	char* res = guess_name("not_there", &confidence);
	XCTAssertEqual(res,NULL);
	res = guess_name("testdomain", &confidence);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res,"test"),0);
	XCTAssertEqual(confidence,0.95);
	add_dns_conn("testdomain", "test2");
	res = guess_name("testdomain", &confidence);
	XCTAssertEqual(confidence,0.5);
	
	//test save and reload
	save_dns_conn_list("dns");
	XCTAssertEqual(load_dns_conn_list("/tmp/", "empty"),-1);
	res = guess_name("testdomain", &confidence);
	XCTAssertEqual(res,NULL);
	XCTAssertEqual(load_dns_conn_list("/tmp/", "dns"),0);
	res = guess_name("testdomain", &confidence);
	XCTAssertNotEqual(res,NULL);
	}
@end
