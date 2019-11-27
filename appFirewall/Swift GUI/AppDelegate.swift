//
//  AppDelegate.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa
import ServiceManagement
import os

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {
	
	//--------------------------------------------------------
	// private variables
	// timer for periodic polling ...
	var timer : Timer!
	var timer_stats: Timer!
	var count_stats: Int = 0
	// menubar button ...
	var statusItem = NSStatusBar.system.statusItem(withLength:NSStatusItem.squareLength)
	// create a preference pane instance
	let prefController : PreferenceViewController = NSStoryboard(name:"Main", bundle:nil).instantiateController(withIdentifier: "PreferenceViewController") as! PreferenceViewController
	
	//--------------------------------------------------------
	// menu item event handlers
	
	@IBAction func PreferencesMenu(_ sender: Any) {
		// handle click on preferences menu item by opening preferences window
		let myWindow = NSWindow(contentViewController: prefController)
		myWindow.styleMask.remove(.miniaturizable) // disable close button, per apple guidelines for preference panes
		myWindow.styleMask.remove(.resizable) // fixed size
		let vc = NSWindowController(window: myWindow)
		vc.showWindow(self)
	}
	
	@IBAction func ClearLog(_ sender: Any) {
		// handle click on "Clear Connection Log" menu entry
		//print("clear log")
		clear_log()
	}
		
	@IBAction func copy(_ sender: Any) {
			// handle Copy menu item by passing on to relevant view
			// (automated handling doesn't work for some reason)
			//print("copy AppDelegate")
			let app = NSApplication.shared
			//print(app.mainWindow, app.isHidden)
			if (app.mainWindow == nil){ return }
			guard let tc : NSTabViewController = app.mainWindow?.contentViewController as? NSTabViewController else { return }
			let i = tc.selectedTabViewItemIndex
			let v = tc.tabViewItems[i] // the currently active TabViewItem
			//print(tc.tabViewItems)
			//print(v.label)
			if (v.label == "Active Connections") {
				let c = v.viewController as! ActiveConnsViewController
				c.copy(sender: nil)
			} else if (v.label == "Black List") {
				let c = v.viewController as! BlockListViewController
				c.copy(sender: nil)
			} else if (v.label == "Connection Log") {
				let c = v.viewController as! LogViewController
				c.copy(sender: nil)
			} else if (v.label == "White List") {
				let c = v.viewController as! WhiteListViewController
				c.copy(sender: nil)
			}
		}
	
	@IBAction func SelectAll(_ sender: Any) {
		// handle click on "Select All" menu entry
			let app = NSApplication.shared
			//print(app.mainWindow, app.isHidden)
			if (app.mainWindow == nil){ return }
			guard let tc : NSTabViewController = app.mainWindow?.contentViewController as? NSTabViewController else { return }
			let i = tc.selectedTabViewItemIndex
			let v = tc.tabViewItems[i] // the currently active TabViewItem
			//print(tc.tabViewItems)
			//print(v.label)
				if (v.label == "Active Connections") {
				let c = v.viewController as! ActiveConnsViewController
				c.selectall(sender:nil)
			} else if (v.label == "Black List") {
				let c = v.viewController as! BlockListViewController
				c.selectall(sender:nil)
			} else if (v.label == "Connection Log") {
				let c = v.viewController as! LogViewController
				c.selectall(sender:nil)
			} else if (v.label == "White List") {
				let c = v.viewController as! LogViewController
				c.selectall(sender:nil)
			}
		}
	
	// handle click on menubar item
	@objc func openapp(_ sender: Any?) {
		// reopen active connections window
		// surely there is a nicer way to do this !
		let app = NSApplication.shared
		//print(app.mainWindow, app.isHidden)
		if (app.mainWindow == nil){
			let storyboard = NSStoryboard(name:"Main", bundle:nil)
			let controller : NSTabViewController = storyboard.instantiateController(withIdentifier: "TabViewController") as! NSTabViewController
			let myWindow = NSWindow(contentViewController: controller)
			let vc = NSWindowController(window: myWindow)
			let tab_index = UserDefaults.standard.integer(forKey: "tab_index") // get tab
			controller.tabView.selectTabViewItem(at:tab_index)
			vc.showWindow(self)
			NSApp.activate(ignoringOtherApps: true) // bring window to front of other apps
		}
	}
		
	//--------------------------------------------------------
	@objc func stats() {
		print_stats() // output current performance stats
		count_stats = count_stats+1
		if (count_stats>6) {
			print_escapees()
			count_stats = 0
		}
	}
	
	@objc func refresh() {
		// note: state is saved on window close, no need to do it here
		// (and if we do it here it might be interrupted by a window
		// close event and lead to file corruption
		//save_log(); save_blocklist(); save_dns_cache()
		
		// check is listener thread (for talking with helper process that
		// has root priviledge) has run into trouble -- if so, its fatal
		if (Int(listener_error()) != 0) {
				raise(SIGCHLD)
		}
		// rotate log files if they're getting too large
		save_log() // this will flush human-readable log file
		log_rotate(logName: "log.txt")
		load_log() // we reopen human-readable log file
		log_rotate(logName: "app_log.txt")

		// update menubar button tooltip
		if let button = statusItem.button {
			button.toolTip="appFirewall ("+String(get_num_conns_blocked())+" blocked)"
		}
	}
	
	//--------------------------------------------------------
	// application event handlers
	
	func applicationWillFinishLaunching(_ aNotification: Notification) {
		
		//print(String(Double(DispatchTime.now().uptimeNanoseconds)/1.0e9),"starting applicationWillFinishLaunching()")
		// create storage dir if it doesn't already exist
		make_data_dir()
		
		// redirect C logging from stdout to logfile (in storage dir, so
		// important to call make_data_dir() first
		redirect_stdout()
		
		if (is_app_already_running()) {
			exit_popup(msg:"appFirewall is already running!")
			//exit(1)
		}

		// install appFirewall-Helper, if not already installed
		start_helper()

		// setup menubar action
		let val = UserDefaults.standard.integer(forKey: "Number of connections blocked")
		set_num_conns_blocked(Int32(val))
		if let button = statusItem.button {
			button.image = NSImage(named:NSImage.Name("StatusBarButtonImage"))
			button.toolTip="appFirewall ("+String(get_num_conns_blocked())+" blocked)"
			button.action = #selector(openapp(_:))
		}
		
		// set default display state for GUI
		UserDefaults.standard.register(defaults: ["active_asc":true])
		UserDefaults.standard.register(defaults: ["blocklist_asc":true])
		UserDefaults.standard.register(defaults: ["log_asc":false])
		UserDefaults.standard.register(defaults: ["log_show_blocked":3])
				
		// set default logging level
		UserDefaults.standard.register(defaults: ["logging_level":2])
		// can change this at command line using "defaults write" command
		let log_level = UserDefaults.standard.integer(forKey: "logging_level")
		set_logging_level(Int32(log_level))
		init_stats();

		// set whether to use dtrace assistance or not
		UserDefaults.standard.register(defaults: ["dtrace":1])
		let dtrace = UserDefaults.standard.integer(forKey: "dtrace")
		
		// set up handler to catch C errors
		setup_sigterm_handler()
		
		// reload state
		load_log(); load_blocklist(); load_whitelist()
		load_dns_cache()
		prefController.load_hostlists() // might be slow?

		// start listeners
		// this can be slow since it blocks while making network connection to helper
    DispatchQueue.global(qos: .background).async {
			start_helper_listeners(Int32(dtrace))
		}
		
		// schedule house-keeping ...
		timer = Timer.scheduledTimer(timeInterval: 10, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late
		timer_stats = Timer.scheduledTimer(timeInterval: 10, target: self, selector: #selector(stats), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late

		//print(String(Double(DispatchTime.now().uptimeNanoseconds)/1.0e9),"finished applicationWillFinishLaunching()")
		//let t = NSApplication.shared.mainWindow?.contentViewController as? NSTabViewController
		//t?.tabView.selectedTabViewItem?.viewController?.viewWillAppear()
	}

	func applicationWillTerminate(_ aNotification: Notification) {
		// Insert code here to tear down your application
		// NB: don't think this function is *ever* called
		print("stopping")
		//stop_listener()
		stop_helper_listeners()
	}
	
	func applicationDidEnterBackground(_ aNotification: Notification) {
		// Insert code here to tear down your application
		// NB: don't think this function is *ever* called
		print("going into background")
	}

}

