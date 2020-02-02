//
//  blacklist_tests.m
//  appFirewallTests
//
//  Created by Doug Leith on 01/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>
#include "../C workers/util.h"
#include "../C workers/conn_list.h"
#include "../C workers/blocklists.h"
#include "../C workers/hostlists.h"
#include "../C workers/is_blocked.h"

@interface blacklist_tests : XCTestCase

@end

@implementation blacklist_tests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testConnList {

	// create list and add items
	set_path("/tmp/");
	load_connlist(get_blocklist(),"empty");
	XCTAssertEqual(get_connlist_size(get_blocklist()),0)
	;
	bl_item_t item, item2, item3, item4;
	strcpy(item.name,"test"); strcpy(item2.name,"test2"); strcpy(item3.name,"test3"); strcpy(item4.name,"<all apps>");
	strcpy(item.domain,"testdomain"); strcpy(item2.domain,"testdomain2"); strcpy(item3.domain,"<all connections>"); strcpy(item4.domain,"testdomain4");
	strcpy(item.addr_name,"testaddr"); strcpy(item2.addr_name,"testaddr2"); strcpy(item3.addr_name,"testaddr3"); strcpy(item3.addr_name,"testaddr4");
	
	XCTAssertEqual(strcmp(cl_hash(&item),"test:testdomain"),0);
	bl_item_t* it1 = &item, *it2 = &item2;
	XCTAssertLessThan(cl_sort_cmp(&it1,&it2),0);
	XCTAssertGreaterThan(cl_sort_cmp(&it2,&it1),0);

	add_connitem(get_blocklist(),&item);
	XCTAssertEqual(get_connlist_size(get_blocklist()),1);
	bl_item_t *res = get_connlist_item(get_blocklist(),0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	add_connitem(get_blocklist(),&item2);
	XCTAssertEqual(get_connlist_size(get_blocklist()),2);
	res = get_connlist_item(get_blocklist(),0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = get_connlist_item(get_blocklist(),1);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item2.name),0);

	// check lookup
	res = in_connlist_htab(get_blocklist(),&item,0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = in_connlist_htab(get_blocklist(),&item3,0); // not in list
	XCTAssertEqual(res,NULL);
	
	// check delete
	XCTAssertEqual(del_connitem(get_blocklist(),&item3),0); // delete non-existent item
	XCTAssertEqual(get_connlist_size(get_blocklist()),2);
	XCTAssertEqual(del_connitem(get_blocklist(),&item),0);
	XCTAssertEqual(get_connlist_size(get_blocklist()),1);
	res = get_connlist_item(get_blocklist(),0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item2.name),0);

	// extras
	add_connitem(get_blocklist(),&item3); // add conn all domains item via main API
	XCTAssertEqual(get_connlist_size(get_blocklist()),2);
	res = in_connalllist_htab(get_blocklist(),&item3, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_connlist_htab(get_blocklist(),&item3,0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(del_connitem(get_blocklist(),&item3),0);
	XCTAssertEqual(get_connlist_size(get_blocklist()),1);
	res = in_connalllist_htab(get_blocklist(),&item3, 0);
	XCTAssertEqual(res,NULL);
	res = in_connlist_htab(get_blocklist(),&item3,0);
	XCTAssertEqual(res,NULL);

	add_connallitem(get_blocklist(),&item3); // and via subsidiary API
	XCTAssertEqual(get_connlist_size(get_blocklist()),2);
	res = in_connalllist_htab(get_blocklist(),&item3, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_connalllist_htab(get_blocklist(),&item2, 0); // non-existent entry
	XCTAssertEqual(res,NULL);

	add_connitem(get_blocklist(),&item4); // add conn all apps item via main API
	XCTAssertEqual(get_connlist_size(get_blocklist()),3);
	res = in_conndomainlist_htab(get_blocklist(),&item4, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_connlist_htab(get_blocklist(),&item4,0);
	XCTAssertNotEqual(res,NULL);
	res = in_conndomainlist_htab(get_blocklist(),&item3,0);
	XCTAssertEqual(res,NULL);
	XCTAssertEqual(del_connitem(get_blocklist(),&item4),0);
	XCTAssertEqual(get_connlist_size(get_blocklist()),2);
	res = in_conndomainlist_htab(get_blocklist(),&item4, 0); // non-existent entry
	XCTAssertEqual(res,NULL);

	add_conndomainitem(get_blocklist(),&item4); // and via subsidiary API
	res = in_conndomainlist_htab(get_blocklist(),&item4, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_connlist_htab(get_blocklist(),&item4,0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(del_connitem(get_blocklist(),&item4),0);

	// check swift utils
	XCTAssertEqual(strcmp(get_connlist_item_name(&item),item.name),0);
	XCTAssertEqual(strcmp(get_connlist_item_domain(&item),item.domain),0);
	XCTAssertEqual(strcmp(get_connlist_item_addrname(&item),item.addr_name),0);
	add_connitem2(get_blocklist(),item4.name, item4.domain);
	res = in_connlist_htab(get_blocklist(),&item4,0);
	XCTAssertNotEqual(res,NULL);
	res = in_conndomainlist_htab(get_blocklist(),&item4, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(get_connlist_size(get_blocklist()),3);
	conn_t c;
	strcpy(c.name,"connname"); strcpy(c.domain,"conndomain");
	strcpy(c.src_addr_name,"connsrc_name"); strcpy(c.dst_addr_name,"conndst_name");
	bl_item_t b = conn_to_bl_item(&c);
	XCTAssertEqual(strcmp(b.name,c.name),0);
	XCTAssertEqual(strcmp(b.domain,c.domain),0);
	XCTAssertEqual(strcmp(b.addr_name,c.dst_addr_name),0);

	// load and save
	save_connlist(get_blocklist(),"bl.dat");
	XCTAssertEqual(del_connitem(get_blocklist(),&item4),0);
	XCTAssertEqual(get_connlist_size(get_blocklist()),2);
	load_connlist(get_blocklist(),"bl.dat");
	XCTAssertEqual(get_connlist_size(get_blocklist()),3);
	res = in_connlist_htab(get_blocklist(),&item4,0);
	XCTAssertNotEqual(res,NULL);
	res = in_conndomainlist_htab(get_blocklist(),&item4, 0);
	XCTAssertNotEqual(res,NULL);
	load_connlist(get_blocklist(),"bl2.dat"); // load from non-existent file
	XCTAssertEqual(get_connlist_size(get_blocklist()),0);

	// sorting
	add_connitem(get_blocklist(),&item);
	add_connitem(get_blocklist(),&item2);
	res = get_connlist_item(get_blocklist(),0);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = get_connlist_item(get_blocklist(),1);
	XCTAssertEqual(strcmp(res->name,item2.name),0);
	sort_conn_list(get_blocklist(),-1, -1);
	res = get_connlist_item(get_blocklist(),0);
	XCTAssertEqual(strcmp(res->name,item2.name),0);
	res = get_connlist_item(get_blocklist(),1);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	sort_conn_list(get_blocklist(),1, 0);
	res = get_connlist_item(get_blocklist(),0);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = get_connlist_item(get_blocklist(),1);
	XCTAssertEqual(strcmp(res->name,item2.name),0);
	}
	
- (void)testBlockLists {
	int res = load_blocklistfile("BlackLists/dougs_blocklist.txt");
	XCTAssertEqual(res,0);
	bl_item_t item, item2, item3;
	strcpy(item.name,"test"); strcpy(item2.name,"Spotify");
	strcpy(item.domain,"testdomain"); strcpy(item2.domain,"www.spotify.com");
	// app for which specific domain is blocked
	strcpy(item.addr_name,"testaddr"); strcpy(item2.addr_name,"www.spotify.com");
	XCTAssertEqual(in_blocklists_htab(&item),NULL); //not in table, not blocked
	XCTAssertNotEqual(in_blocklists_htab(&item2),NULL); // blocked
	// app for which all domains are blocked
	strcpy(item3.name,"Microsoft Power"); strcpy(item3.domain,"anything");
	XCTAssertNotEqual(in_blocklists_htab(&item3),NULL);
	// app for which domain is whitelisted (and rest are blocked)
	strcpy(item3.name,"Dropbox"); strcpy(item3.domain,"client.dropbox.com");
	XCTAssertEqual(in_blocklists_htab(&item3),NULL);
	// domain for which all apps are blocked
	strcpy(item3.name,"any"); strcpy(item3.domain,"adservice.google.ie");
	XCTAssertNotEqual(in_hostlist_htab("adservice.google.ie"),NULL);
	}

- (void)testHostLists {
	int res = load_hostsfile("BlackLists/dougs_list.txt");
	XCTAssertEqual(res,0);
	XCTAssertNotEqual(in_hostlist_htab("adeventtracker.spotify.com"),NULL); // in list
	XCTAssertEqual(in_hostlist_htab("any"),NULL); //  not in list
	add_hostlist("any");
	XCTAssertNotEqual(in_hostlist_htab("any"),NULL); //  not in list
	}

- (void)testisBlocked {
	XCTAssertEqual(load_blocklistfile("BlackLists/dougs_blocklist.txt"),0);
	bl_item_t item;
	strcpy(item.name,"Dropbox"); strcpy(item.domain,"client.dropbox.com");
	XCTAssertEqual(is_white(&item),0);
	XCTAssertEqual(is_blocked(&item),0);
	XCTAssertEqual(blocked_status(&item),0);
	strcpy(item.name,"any"); strcpy(item.domain,"adservice.google.ie");
	XCTAssertEqual(is_white(&item),0);
	XCTAssertEqual(is_blocked(&item),2);
	XCTAssertEqual(blocked_status(&item),2);
	strcpy(item.name,"test"); strcpy(item.domain,"testdomain");
	add_connitem(get_blocklist(),&item);
	XCTAssertEqual(is_white(&item),0);
	XCTAssertEqual(is_blocked(&item),1);
	XCTAssertEqual(blocked_status(&item),1);
	add_connitem(get_whitelist(),&item);
	XCTAssertEqual(is_white(&item),1);
	XCTAssertEqual(is_blocked(&item),0);
	XCTAssertEqual(blocked_status(&item),1);
	}
	
/*- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }]
	}
*/

@end
