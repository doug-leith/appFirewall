//
//  tests.m
//  appFirewallTests
//
//  Created by Doug Leith on 03/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>

@interface tests : XCTestCase

@end

#include "../util.h"

@implementation tests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testUtils {
		char test[1024]; strcpy(test,"  123 4 ");
		XCTAssertEqual(strcmp(trimwhitespace(test),"123 4"),0);
		int are_addr_same(int af, struct in6_addr* addr1, struct in6_addr* addr2);

		struct in6_addr a, a2;
		memset(&a,1,sizeof(a)); 
		memcpy(&a2,&a,sizeof(a2));
		XCTAssertEqual(are_addr_same(AF_INET,&a,&a2),1);
		XCTAssertEqual(are_addr_same(AF_INET6,&a,&a2),1);
		memset(&a2,0,sizeof(a2));
		XCTAssertEqual(are_addr_same(AF_INET,&a,&a2),0);
		XCTAssertEqual(are_addr_same(AF_INET6,&a,&a2),0);
}

// need to add a bunch of stubs to allow decent testing of the rest
- (void)testPcapSniffer {
}

- (void)testSndRST {
}

- (void)testCatchEscapee {
}

- (void)testCmd {
}

- (void)testCodesign {
}

@end
