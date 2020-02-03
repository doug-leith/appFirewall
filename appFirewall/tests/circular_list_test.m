//
//  circular_list_test.m
//  appFirewall
//
//  Created by Doug Leith on 01/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>
#include "../C workers/util.h"
#include "../C workers/table.h"
#include "../C workers/circular_list.h"

char* test_hash(const void *it) {
	void* temp = malloc(strlen(it)+1);
	strcpy(temp,it);
	return temp;
}

@interface circular_list_test : XCTestCase

@end

@implementation circular_list_test

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testTable {
		int value1=1, value2=2;
    Hashtable* table = hashtable_new(1000);
    XCTAssertNotEqual(table,NULL);
    
    // put value into table and retrieve it
    void* res = hashtable_put(table,"key1",&value1);
    XCTAssertEqual(res,NULL);
		res = hashtable_get(table,"key1");
    XCTAssertNotEqual(res, NULL);
    XCTAssertEqual(*((int*)res),value1);
    
    // add duplicate
    res = hashtable_put(table,"key1",&value2);
    XCTAssertNotEqual(res,NULL);
    XCTAssertEqual(*((int*)res),value1);
		res = hashtable_get(table,"key1");
		XCTAssertNotEqual(res,NULL);
		XCTAssertEqual(*((int*)res),value2);

		// remove
		res = hashtable_remove(table, "key1");
		XCTAssertNotEqual(res,NULL);
		XCTAssertEqual(*((int*)res),value2);
		
		// and now try to remove non-existent entry
		res = hashtable_remove(table, "key1");
		XCTAssertEqual(res,NULL);
		
		// and free table
		hashtable_free(table);
}

- (void)testList {
	list_t l = LIST_INITIALISER;
	
	// create list, add an item and fetch it
	init_list(&l, test_hash, NULL, 0, -1, "test");
	XCTAssertNotEqual(&l,NULL);
	XCTAssertEqual(get_list_size(&l),0);
	char *item="test", *item2="test2";
	void* res = add_item(&l, item, strlen(item)+1);
	XCTAssertEqual(res,NULL);
	XCTAssertEqual(get_list_size(&l),1);
	res = get_list_item(&l, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(*(char*)res,*item);
	res = in_list(&l, item, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(*(char*)res,*item);
	XCTAssertEqual(find_item_row(&l,item),0);

	// add duplicate
	res = add_item(&l, item, strlen(item));
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item),0);
	XCTAssertEqual(get_list_size(&l),1);
	res = get_list_item(&l, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item),0);
	res = in_list(&l, item, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(*(char*)res,*item);
	XCTAssertEqual(find_item_row(&l,item),0);
	XCTAssertEqual(find_item_row(&l,item2),1); // lookup for non-existent item
	
	// add second and fetch
	res = add_item(&l, item2, strlen(item2)+1);
	XCTAssertEqual(res,NULL);
	XCTAssertEqual(get_list_size(&l),2);
	res = get_list_item(&l, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item),0);
	res = get_list_item(&l, 1);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item2),0);
	res = in_list(&l, item2, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(*(char*)res,*item2);
	XCTAssertEqual(find_item_row(&l,item),0);
	XCTAssertEqual(find_item_row(&l,item2),1);

	// del item
	XCTAssertEqual(del_item(&l,item),0);
	XCTAssertEqual(del_item(&l,item),-1); //second delete fails
	XCTAssertEqual(get_list_size(&l),1);
	XCTAssertEqual(in_list(&l, item, 0),NULL);
	res = in_list(&l, item2, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(*(char*)res,*item2);
	res = get_list_item(&l, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item2),0);

	add_item_to_htab(&l, item);
	res = in_list(&l, item, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(*(char*)res,*item);
	del_from_htab(&l, item);
	res = in_list(&l, item, 0);
	XCTAssertEqual(res,NULL);

	clear_list(&l);
	XCTAssertEqual(get_list_size(&l),0);
	res = in_list(&l, item, 0);
	XCTAssertEqual(res,NULL);
	free_list(&l);
	}

	int sort_cmp(const void* it1, const void* it2){
		return strcasecmp(it1,it2);
	}
	
- (void)testCircularList {
	// check that circular list wraps around as expected
	
	list_t l = LIST_INITIALISER;
	init_list(&l, test_hash, NULL, 1, 2, "test");
	XCTAssertNotEqual(&l,NULL);
	XCTAssertEqual(get_list_size(&l),0);
	char *item="test", *item2="test3", *item3="test2";
	void* res = add_item(&l, item, strlen(item)+1);
	XCTAssertEqual(get_list_size(&l),1);
	res = get_list_item(&l, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item),0);

	res = add_item(&l, item2, strlen(item2)+1);
	XCTAssertEqual(get_list_size(&l),2);
	res = get_list_item(&l, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item),0);
	res = get_list_item(&l, 1);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item2),0);

	res = add_item(&l, item3, strlen(item3)+1);
	XCTAssertEqual(get_list_size(&l),2);
	res = get_list_item(&l, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item2),0);
	res = get_list_item(&l, 1);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item3),0);

	// check sorting
	sort_list(&l, sort_cmp);
	res = get_list_item(&l, 0);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item2),0);
	res = get_list_item(&l, 1);
	XCTAssertNotEqual(res,NULL);
	XCTAssertEqual(strcmp((char*)res,item3),0);
	}

- (void)testSaveList {
	list_t l = LIST_INITIALISER;
	init_list(&l, test_hash, NULL, 1, -1, "test");
	char item[32], item2[32], item3[32];
	strcpy(item,"test"); strcpy(item2,"test3"); strcpy(item3,"test2");
	//char *item="test", *item2="test3", *item3="test2";
	void* res = add_item(&l, item, 32);
	res = add_item(&l, item2, 32);
	res = add_item(&l, item3, 32);
	save_list(&l, "/tmp/list.dat", 32, 0);
	
	list_t l2 = LIST_INITIALISER;
	init_list(&l2, test_hash, NULL, 1, -1, "test2");
	// test error cases
	XCTAssertEqual(load_list(&l2, "/tmp/list.dat", 32, 1),0);
	XCTAssertEqual(load_list(&l2, "/tmp/list2.dat", 32, 0),-1);
	XCTAssertEqual(load_list(&l2, "/tmp/list.dat", 1, 1),0);
	XCTAssertEqual(load_list(&l2, "/tmp/list.dat", 33, 1),0);
	
	XCTAssertEqual(load_list(&l2, "/tmp/list.dat", 32, 0),1);
	XCTAssertEqual(get_list_size(&l2),3);
	res = get_list_item(&l2, 0);
	XCTAssertEqual(strcmp((char*)res,item),0);
	res = get_list_item(&l2, 1);
	XCTAssertEqual(strcmp((char*)res,item2),0);
	res = get_list_item(&l2, 2);
	XCTAssertEqual(strcmp((char*)res,item3),0);
	}

/*- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}*/

@end
