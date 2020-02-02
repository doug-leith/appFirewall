//
//  pid_conn_info_test.m
//  appFirewallTests
//
//  Created by Doug Leith on 01/02/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

#import <XCTest/XCTest.h>

@interface pid_conn_info_test : XCTestCase

@end

@implementation pid_conn_info_test

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testExample {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
}

/*
 int get_pid_name(int pid, char* name, uint32_t *status);
 int find_pid(conn_raw_t *c, char*name, int syn);
 void cache_pid(int pid, char* name);

 void init_pid_lists(void);
 int find_fds(int pid, char* name, list_t* new_pid_list, int full_refresh);
 int refresh_active_conns(int full_refresh);

 void start_pid_watcher(void);
 void signal_pid_watcher(int force, int full_refresh);
 void set_pid_watcher_hook(void (*hook)(void));
 int get_pid_changed(void);
 void clear_pid_changed(void);
 void find_escapees(void);
 void *catch_escapee(void *ptr);

 //swift
 conn_t get_gui_conn(int_sw row);
 void free_conn(conn_t* c);
 int_sw get_num_gui_conns(void);
 void print_escapees(void);
 void update_gui_pid_list(void);
 */
- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
