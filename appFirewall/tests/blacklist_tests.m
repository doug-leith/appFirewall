//
//  blacklist_tests.m
//  appFirewallTests
//
//  Created by Doug Leith on 01/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>
#include "../C workers/util.h"
#include "../C workers/blocklist.h"
#include "../C workers/whitelist.h"
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

- (void)testBlockList {

	// create list and add items
	set_path("/tmp/");
	load_blocklist("empty");
	XCTAssertEqual(get_blocklist_size(),0)
	;
	bl_item_t item, item2, item3, item4;
	strcpy(item.name,"test"); strcpy(item2.name,"test2"); strcpy(item3.name,"test3"); strcpy(item4.name,"<all apps>");
	strcpy(item.domain,"testdomain"); strcpy(item2.domain,"testdomain2"); strcpy(item3.domain,"<all connections>"); strcpy(item4.domain,"testdomain4");
	strcpy(item.addr_name,"testaddr"); strcpy(item2.addr_name,"testaddr2"); strcpy(item3.addr_name,"testaddr3"); strcpy(item3.addr_name,"testaddr4");
	
	XCTAssertEqual(strcmp(bl_hash(&item),"test:testdomain"),0);
	bl_item_t* it1 = &item, *it2 = &item2;
	XCTAssertLessThan(bl_sort_cmp(&it1,&it2),0);
	XCTAssertGreaterThan(bl_sort_cmp(&it2,&it1),0);

	add_blockitem(&item);
	XCTAssertEqual(get_blocklist_size(),1);
	bl_item_t *res = get_blocklist_item(0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	add_blockitem(&item2);
	XCTAssertEqual(get_blocklist_size(),2);
	res = get_blocklist_item(0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = get_blocklist_item(1);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item2.name),0);

	// check lookup
	res = in_blocklist_htab(&item,0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = in_blocklist_htab(&item3,0); // not in list
	XCTAssertEqual(res,NULL);
	
	// check delete
	XCTAssertEqual(del_blockitem(&item3),0); // delete non-existent item
	XCTAssertEqual(get_blocklist_size(),2);
	XCTAssertEqual(del_blockitem(&item),0);
	XCTAssertEqual(get_blocklist_size(),1);
	res = get_blocklist_item(0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item2.name),0);

	// extras
	add_blockitem(&item3); // add block all domains item via main API
	XCTAssertEqual(get_blocklist_size(),2);
	res = in_blockalllist_htab(&item3, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_blocklist_htab(&item3,0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(del_blockitem(&item3),0);
	XCTAssertEqual(get_blocklist_size(),1);
	res = in_blockalllist_htab(&item3, 0);
	XCTAssertEqual(res,NULL);
	res = in_blocklist_htab(&item3,0);
	XCTAssertEqual(res,NULL);

	add_blockallitem(&item3); // and via subsidiary API
	XCTAssertEqual(get_blocklist_size(),2);
	res = in_blockalllist_htab(&item3, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_blockalllist_htab(&item2, 0); // non-existent entry
	XCTAssertEqual(res,NULL);

	add_blockitem(&item4); // add block all apps item via main API
	XCTAssertEqual(get_blocklist_size(),3);
	res = in_blockdomainlist_htab(&item4, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_blocklist_htab(&item4,0);
	XCTAssertNotEqual(res,NULL);
	res = in_blockdomainlist_htab(&item3,0);
	XCTAssertEqual(res,NULL);
	XCTAssertEqual(del_blockitem(&item4),0);
	XCTAssertEqual(get_blocklist_size(),2);
	res = in_blockdomainlist_htab(&item4, 0); // non-existent entry
	XCTAssertEqual(res,NULL);

	add_blockdomainitem(&item4); // and via subsidiary API
	res = in_blockdomainlist_htab(&item4, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_blocklist_htab(&item4,0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(del_blockitem(&item4),0);

	// check swift utils
	XCTAssertEqual(strcmp(get_blocklist_item_name(&item),item.name),0);
	XCTAssertEqual(strcmp(get_blocklist_item_domain(&item),item.domain),0);
	XCTAssertEqual(strcmp(get_blocklist_item_addrname(&item),item.addr_name),0);
	add_blockitem2(item4.name, item4.domain);
	res = in_blocklist_htab(&item4,0);
	XCTAssertNotEqual(res,NULL);
	res = in_blockdomainlist_htab(&item4, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(get_blocklist_size(),3);
	conn_t c;
	strcpy(c.name,"connname"); strcpy(c.domain,"conndomain");
	strcpy(c.src_addr_name,"connsrc_name"); strcpy(c.dst_addr_name,"conndst_name");
	bl_item_t b = conn_to_bl_item(&c);
	XCTAssertEqual(strcmp(b.name,c.name),0);
	XCTAssertEqual(strcmp(b.domain,c.domain),0);
	XCTAssertEqual(strcmp(b.addr_name,c.dst_addr_name),0);

	// load and save
	save_blocklist("bl.dat");
	XCTAssertEqual(del_blockitem(&item4),0);
	XCTAssertEqual(get_blocklist_size(),2);
	load_blocklist("bl.dat");
	XCTAssertEqual(get_blocklist_size(),3);
	res = in_blocklist_htab(&item4,0);
	XCTAssertNotEqual(res,NULL);
	res = in_blockdomainlist_htab(&item4, 0);
	XCTAssertNotEqual(res,NULL);
	load_blocklist("bl2.dat"); // load from non-existent file
	XCTAssertEqual(get_blocklist_size(),0);

	// sorting
	add_blockitem(&item);
	add_blockitem(&item2);
	res = get_blocklist_item(0);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = get_blocklist_item(1);
	XCTAssertEqual(strcmp(res->name,item2.name),0);
	sort_block_list(-1, -1);
	res = get_blocklist_item(0);
	XCTAssertEqual(strcmp(res->name,item2.name),0);
	res = get_blocklist_item(1);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	sort_block_list(1, 0);
	res = get_blocklist_item(0);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = get_blocklist_item(1);
	XCTAssertEqual(strcmp(res->name,item2.name),0);
	}

- (void)testWhiteList {
	// cut and paste of blocklist tests
	// create list and add items
	set_path("/tmp/");
	load_whitelist("empty");
	XCTAssertEqual(get_whitelist_size(),0)
	;
	bl_item_t item, item2, item3, item4;
	strcpy(item.name,"test"); strcpy(item2.name,"test2"); strcpy(item3.name,"test3"); strcpy(item4.name,"<all apps>");
	strcpy(item.domain,"testdomain"); strcpy(item2.domain,"testdomain2"); strcpy(item3.domain,"<all connections>"); strcpy(item4.domain,"testdomain4");
	strcpy(item.addr_name,"testaddr"); strcpy(item2.addr_name,"testaddr2"); strcpy(item3.addr_name,"testaddr3"); strcpy(item3.addr_name,"testaddr4");
	
	XCTAssertEqual(strcmp(bl_hash(&item),"test:testdomain"),0);
	bl_item_t* it1 = &item, *it2 = &item2;
	XCTAssertLessThan(bl_sort_cmp(&it1,&it2),0);
	XCTAssertGreaterThan(bl_sort_cmp(&it2,&it1),0);

	add_whiteitem(&item);
	XCTAssertEqual(get_whitelist_size(),1);
	bl_item_t *res = get_whitelist_item(0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	add_whiteitem(&item2);
	XCTAssertEqual(get_whitelist_size(),2);
	res = get_whitelist_item(0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = get_whitelist_item(1);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item2.name),0);

	// check lookup
	res = in_whitelist_htab(&item,0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = in_whitelist_htab(&item3,0); // not in list
	XCTAssertEqual(res,NULL);
	
	// check delete
	XCTAssertEqual(del_whiteitem(&item3),0); // delete non-existent item
	XCTAssertEqual(get_whitelist_size(),2);
	XCTAssertEqual(del_whiteitem(&item),0);
	XCTAssertEqual(get_whitelist_size(),1);
	res = get_whitelist_item(0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp(res->name,item2.name),0);

	// extras
	add_whiteitem(&item3); // add white all domains item via main API
	XCTAssertEqual(get_whitelist_size(),2);
	res = in_allowalllist_htab(&item3, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_whitelist_htab(&item3,0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(del_whiteitem(&item3),0);
	XCTAssertEqual(get_whitelist_size(),1);
	res = in_allowalllist_htab(&item3, 0);
	XCTAssertEqual(res,NULL);
	res = in_whitelist_htab(&item3,0);
	XCTAssertEqual(res,NULL);

	add_allowallitem(&item3); // and via subsidiary API
	XCTAssertEqual(get_whitelist_size(),2);
	res = in_allowalllist_htab(&item3, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_allowalllist_htab(&item2, 0); // non-existent entry
	XCTAssertEqual(res,NULL);

	add_whiteitem(&item4); // add white all apps item via main API
	XCTAssertEqual(get_whitelist_size(),3);
	res = in_allowdomainlist_htab(&item4, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_whitelist_htab(&item4,0);
	XCTAssertNotEqual(res,NULL);
	res = in_allowdomainlist_htab(&item3,0);
	XCTAssertEqual(res,NULL);
	XCTAssertEqual(del_whiteitem(&item4),0);
	XCTAssertEqual(get_whitelist_size(),2);
	res = in_allowdomainlist_htab(&item4, 0); // non-existent entry
	XCTAssertEqual(res,NULL);

	add_allowdomainitem(&item4); // and via subsidiary API
	res = in_allowdomainlist_htab(&item4, 0);
	XCTAssertNotEqual(res,NULL);
	res = in_whitelist_htab(&item4,0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(del_whiteitem(&item4),0);

	// check swift utils
	XCTAssertEqual(strcmp(get_whitelist_item_name(&item),item.name),0);
	XCTAssertEqual(strcmp(get_whitelist_item_domain(&item),item.domain),0);
	XCTAssertEqual(strcmp(get_whitelist_item_addrname(&item),item.addr_name),0);
	add_whiteitem2(item4.name, item4.domain);
	res = in_whitelist_htab(&item4,0);
	XCTAssertNotEqual(res,NULL);
	res = in_allowdomainlist_htab(&item4, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(get_whitelist_size(),3);
	conn_t c;
	strcpy(c.name,"connname"); strcpy(c.domain,"conndomain");
	strcpy(c.src_addr_name,"connsrc_name"); strcpy(c.dst_addr_name,"conndst_name");
	bl_item_t b = conn_to_bl_item(&c);
	XCTAssertEqual(strcmp(b.name,c.name),0);
	XCTAssertEqual(strcmp(b.domain,c.domain),0);
	XCTAssertEqual(strcmp(b.addr_name,c.dst_addr_name),0);

	// load and save
	save_whitelist("bl.dat");
	XCTAssertEqual(del_whiteitem(&item4),0);
	XCTAssertEqual(get_whitelist_size(),2);
	load_whitelist("bl.dat");
	XCTAssertEqual(get_whitelist_size(),3);
	res = in_whitelist_htab(&item4,0);
	XCTAssertNotEqual(res,NULL);
	res = in_allowdomainlist_htab(&item4, 0);
	XCTAssertNotEqual(res,NULL);
	load_whitelist("bl2.dat"); // load from non-existent file
	XCTAssertEqual(get_whitelist_size(),0);

	// sorting
	add_whiteitem(&item);
	add_whiteitem(&item2);
	res = get_whitelist_item(0);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = get_whitelist_item(1);
	XCTAssertEqual(strcmp(res->name,item2.name),0);
	sort_white_list(-1, -1);
	res = get_whitelist_item(0);
	XCTAssertEqual(strcmp(res->name,item2.name),0);
	res = get_whitelist_item(1);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	sort_white_list(1, 0);
	res = get_whitelist_item(0);
	XCTAssertEqual(strcmp(res->name,item.name),0);
	res = get_whitelist_item(1);
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
	add_blockitem(&item);
	XCTAssertEqual(is_white(&item),0);
	XCTAssertEqual(is_blocked(&item),1);
	XCTAssertEqual(blocked_status(&item),1);
	add_whiteitem(&item);
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
