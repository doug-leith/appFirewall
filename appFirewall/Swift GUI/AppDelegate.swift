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
	var timer : Timer = Timer()
	var timer_logs : Timer = Timer()
	var timer_stats: Timer = Timer()
	var count_stats: Int = 0
	// menubar button ...
	var statusItem = NSStatusBar.system.statusItem(withLength:NSStatusItem.squareLength)

	//--------------------------------------------------------
	// menu item event handlers
	
	@IBAction func PreferencesMenu(_ sender: Any) {
		// handle click on preferences menu item by opening preferences window
		let prefTabsController : NSTabViewController = NSStoryboard(name:"Main", bundle:nil).instantiateController(withIdentifier: "PreferencesTabs") as! NSTabViewController
		let prefTabsWindow = NSWindow(contentViewController: prefTabsController)
		// hard-wire the size, for some reason window doesn't autosize
		// to fit preferences view
		prefTabsWindow.setContentSize(NSSize(width:602, height:345))
		prefTabsWindow.styleMask.remove(.miniaturizable) // disable close button, per apple guidelines for preference panes
		prefTabsWindow.styleMask.remove(.resizable) // fixed size
		let vc = NSWindowController(window: prefTabsWindow)
		vc.showWindow(self)
		prefTabsWindow.makeKeyAndOrderFront(self) // bring to front
	}
	
	@IBAction func ClearLog(_ sender: Any) {
		// handle click on "Clear Connection Log" menu entry
		//print("clear log")
		clear_log()
	}
	
	func currentAppViewController()->appViewController? {
		guard let tc : NSTabViewController = NSApp.mainWindow?.contentViewController as? NSTabViewController else { print("ERROR on copy: problem getting tab view controller"); return nil}
		let i = tc.selectedTabViewItemIndex
		let v = tc.tabViewItems[i] // the currently active TabViewItem
		guard let c = v.viewController as? appViewController else {print("ERROR on copy: problem getting view controller"); return nil}
		return c
	}
	
	@IBAction func copy(_ sender: Any) {
			// handle Copy menu item by passing on to relevant view
			// (automated handling doesn't work for some reason)
			if (NSApp.mainWindow == nil){ return }
			if let focus = NSApp.keyWindow?.fieldEditor(false, for: self) {
				// there's a text field being edited, call its copy function
				focus.copy(self)
			} else {
				// no active text field, we're copying from table
				currentAppViewController()?.copyLine(sender: nil)
			}
		}


	@IBAction func paste(_ sender: Any) {
		// handle Paste menu item
		if (NSApp.mainWindow == nil){ return }
		if let focus = NSApp.keyWindow?.fieldEditor(false, for: self) {
			// there's a text field being edited, call its paste function
			focus.paste(self)
		} else {
			currentAppViewController()?.pasteLine(sender: nil)
		}
	}
	
	@IBAction func getInfo(_ sender: Any) {
		let app = NSApplication.shared
		if (app.mainWindow == nil){ return }
		guard let tc : NSTabViewController = app.mainWindow?.contentViewController as? NSTabViewController else { print("ERROR on selectAll: problem getting tabview controller"); return }
		let i = tc.selectedTabViewItemIndex
		let v = tc.tabViewItems[i] // the currently active TabViewItem
		guard let c = v.viewController as? appViewController else {print("ERROR on selectAll: problem getting view controller"); return}
		c.getInfo(sender:nil)
	}
	
	@IBAction func SelectAll(_ sender: Any) {
		// handle click on "Select All" menu entry
			let app = NSApplication.shared
			//print(app.mainWindow, app.isHidden)
			if (app.mainWindow == nil){ return }
			guard let tc : NSTabViewController = app.mainWindow?.contentViewController as? NSTabViewController else { print("ERROR on selectAll: problem getting tabview controller"); return }
			let i = tc.selectedTabViewItemIndex
			let v = tc.tabViewItems[i] // the currently active TabViewItem
			//print(tc.tabViewItems)
			//print(v.label)
			guard let c = v.viewController as? appViewController else {print("ERROR on selectAll: problem getting view controller"); return}
			c.selectall(sender:nil)
		}
	
	
	@IBAction func checkForUpdates(_ sender: NSMenuItem) {
		doCheckForUpdates(quiet: false, autoUpdate: false)
	}
	
	
	@IBAction func restartHelper(_ sender: Any) {
		UserDefaults.standard.set(true, forKey: "force_helper_restart")
		restart_app() 
	}
	
	@IBAction func showSampleFolder(_ sender: NSMenuItem) {
		if let sampleDir = getSampleDir() {
			NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath:sampleDir)])
		}
	}
	
	func disableMenu() {
		if (Config.getUseMenuBar()) {
			// hide the dock icon and main menu
			NSApp.setActivationPolicy(.accessory)
		}
	}
	
	func enableMenu() {
		// show the dock icon and main menu
		NSApp.setActivationPolicy(.regular)
		// menu doesn't reactivate unless we change focus away from our app
		// and then back again, see https://stackoverflow.com/questions/41340071/macos-menubar-application-main-menu-not-being-displayed/43780588#43780588
		if (NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.dock").first?.activate(options: []))! {
				 let deadlineTime = DispatchTime.now() + .milliseconds(200)
				 DispatchQueue.main.asyncAfter(deadline: deadlineTime) {
				 NSApp.setActivationPolicy(.regular)
							NSApp.activate(ignoringOtherApps: true)
				 }
		}
	}
	
	// handle click on menubar item
	@objc func openapp(_ sender: Any?) {
		// reopen window
			
		// if window already exists,and it should since we don't
		// release it on close, then we just reopen it.
		// hopefully this should work almost all of the time
		// (seems like an error if it doesn't work)
		for window in NSApp.windows {
			print(window, window.title)
			// as well as the main window the status bar button has a window
			if (window.title == "appFirewall") {
				print("openapp() restoring existing window")
				window.makeKeyAndOrderFront(self) // bring to front
				window.delegate = self // just being careful
				enableMenu()
				NSApp.activate(ignoringOtherApps: true)
				return
			}
		}
		// fall back to constructing window from scratch.
		// this is an error condition, just trying to recover gracefully
		print("WARNING: openapp() falling back to creating new window")
		if (NSApp.mainWindow == nil){
			let storyboard = NSStoryboard(name:"Main", bundle:nil)
			print("openapp(): got storyboard")
			guard let controller : appTabViewController = storyboard.instantiateController(withIdentifier: "TabViewController") as? appTabViewController else {print("openapp(): problem creating viewcontroller"); return}
			print("openapp(): got controller")
			let myWindow = NSWindow(contentViewController: controller)
			print("openapp(): got window")
			myWindow.delegate = self
			let vc = NSWindowController(window: myWindow)
			print("openapp(): got window controller")
			vc.showWindow(self)
			print("openapp(): show window")
			NSApp.activate(ignoringOtherApps: true) // bring window to front of other apps
			enableMenu()
		}
	}
		
	//--------------------------------------------------------
	@objc func stats() {
		print_stats() // output current performance stats
		count_stats = count_stats+1
		if (count_stats>0) {
			print_escapees()
			count_stats = 0
		}
	}
	
	@objc func refresh() {
		// note: state is saved on window close, no need to do it here
		// (and if we do it here it might be interrupted by a window
		// close event and lead to file corruption
		
		// check if listener thread (for talking with helper process that
		// has root privilege) has run into trouble -- if so, its fatal
		if (Int(check_for_error()) != 0) {
				exit_popup(msg:String(cString: get_error_msg()), force:Int(get_error_force()))
				// this call won't return
		}
		// update menubar button tooltip
		if let button = statusItem.button {
			button.toolTip="appFirewall ("+String(get_num_conns_blocked())+" blocked)"
		}
	}

	@objc func refreshLogs() {
		DispatchQueue.global(qos: .background).async {
			save_log(Config.logName)
			
			let date = UserDefaults.standard.object(forKey: "lastSampleDate") as? NSDate
			let numSamples = UserDefaults.standard.integer(forKey: "numSamples")
			if (date == nil) { // first time sent a sample
				UserDefaults.standard.set(NSDate(), forKey: "lastSampleDate")
				UserDefaults.standard.set(0, forKey: "numSamples")
			} else {
				var interval = Config.firstSampleInterval // initially we sample daily
				if numSamples > Config.firstSampleNum {
					interval = Config.sampleInterval // then monthly
				}
				if let diff = date?.timeIntervalSinceNow {
					if ( (diff < -interval) || Config.testSample) {
						sampleLogData(fname: Config.logTxtName) // send a sample from log file
						UserDefaults.standard.set(NSDate(), forKey: "lastSampleDate")
						UserDefaults.standard.set(numSamples+1, forKey: "numSamples")
					}
				} else {
					print("WARNING: Problem getting time interval in refreshLogs()")
				}
			}
			if (need_log_rotate(logName: Config.logTxtName)) {
				close_logtxt() // close human-readable log file
				log_rotate(logName: Config.logTxtName)
				open_logtxt(Config.logTxtName); // open new log file
				sampleLogData(fname: Config.logTxtName+"0") // send a sample of last log file
				UserDefaults.standard.set(NSDate(), forKey: "lastSampleDate")
			}
			if (need_log_rotate(logName: Config.appLogName)) {
				log_rotate(logName: Config.appLogName)
				redirect_stdout(Config.appLogName); // redirect output to the new log file
			}			
		}
	}

	//--------------------------------------------------------
	// application event handlers
	
	func applicationWillFinishLaunching(_ aNotification: Notification) {
				
		// create storage dir if it doesn't already exist
		make_data_dir()
		
		// redirect C logging from stdout to logfile.  do this early but
		// important to call make_data_dir() first so that logfile has somewhere to live
		redirect_stdout(Config.appLogName)
		
		UserDefaults.standard.register(defaults: ["first_run": true])
		let first = UserDefaults.standard.bool(forKey: "first_run")
		if (first || Config.testFirst) {
			// things to do on first run of app
			if (Config.enableConsentForm > 0) {
				// get consent or exit, we check for this early of course
				let storyboard = NSStoryboard(name:"Main", bundle:nil)
				let controller : ConsentViewController = storyboard.instantiateController(withIdentifier: "ConsentViewController") as! ConsentViewController
				let window = NSWindow(contentViewController: controller)
				window.styleMask.remove(.miniaturizable)
				window.styleMask.remove(.resizable) // fixed size
				// now block here until either user gives consent or the app exits
				NSApp.runModal(for: window)
			}
			// log basic security settings (SIP, gatekeeper etc)
			DispatchQueue.global(qos: .background).async {
				getSecuritySettings()
			}
			UserDefaults.standard.set(false, forKey: "first_run")
		}

		// set default logging level, again do this early
		UserDefaults.standard.register(defaults: ["logging_level":Config.defaultLoggingLevel])
		// can change this at command line using "defaults write" command
		let log_level = UserDefaults.standard.integer(forKey: "logging_level")
		set_logging_level(Int32(log_level))
		init_stats(); // must be done before any C threads are fired up
		
		let restart = UserDefaults.standard.bool(forKey: "restart")
		if (restart) {
			print("Restarting ...")
			UserDefaults.standard.set(false, forKey: "restart")
			var count = 0
			while is_app_already_running() {
				sleep(1) // allow time for previous instance to stop
				count = count+1
				if (count>5) { break }
			}
			print("count = ", count)
		}
		if (is_app_already_running()) {
			exit_popup(msg:"appFirewall is already running!", force: 0)
		}

		// useful for debugging
		let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
		print("appFirewall version: ", appVersion ?? "<not found>")
		// for debugging
		print("process: ")
		print("environment ", ProcessInfo.processInfo.environment)

		UserDefaults.standard.register(defaults: ["signal":-1])
		UserDefaults.standard.register(defaults: ["logcrashes":1])
		let sig = UserDefaults.standard.integer(forKey: "signal")
		let logcrashes = UserDefaults.standard.integer(forKey: "logcrashes")
		if ((sig>0) && (logcrashes>0)) {
			// we had a crash !
			if let backtrace = UserDefaults.standard.object(forKey: "backtrace") as? [String], let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String {
				print("had a crash with signal ",sig," for code release ", version)
				backtrace.forEach{print($0)}
				print("continuing")
				// send report to www.leith.ie/logcrash.php.  post "backtrace=<>&version=<>"]
				var request = URLRequest(url: Config.crashURL); request.httpMethod = "POST"
				var str: String = ""
				for s in backtrace {
					str = str + s + "\n"
				}
				let uploadData=("signal="+String(sig)+"&backtrace="+str+"&version="+version).data(using: .ascii)
				let session = URLSession(configuration: .default)
				let task = session.uploadTask(with: request, from: uploadData)
						{ data, response, error in
						if let error = error {
								print ("error when sending backtrace: \(error)")
								return
						}
						if let resp = response as? HTTPURLResponse {
							if !(200...299).contains(resp.statusCode) {
								print ("server error when sending backtrace: ",resp.statusCode)
							}
						}
				}
				task.resume()
				session.finishTasksAndInvalidate()
				// and clear, so we don't come back here
				UserDefaults.standard.set(-1, forKey: "signal")
			} else {
				print("problem getting backtrace or version from userdefaults after crash")
			}
		}

		// set up handler to catch errors.
		setup_sig_handlers()
	
		// flag to C code when we're testing
		if unitTesting() {
				print("unit testing: true")
				set_unit_testing()
		}

		// install appFirewall-Helper, if not already installed
		UserDefaults.standard.register(defaults: ["force_helper_restart":false])
		let force = UserDefaults.standard.bool(forKey: "force_helper_restart")
		start_helper(force: force)
		// reset, force is one time only
		UserDefaults.standard.set(false, forKey: "force_helper_restart")
		
		/*// setup menubar action
		let val = UserDefaults.standard.integer(forKey: "Number of connections blocked")
		set_num_conns_blocked(Int32(val))
		if let button = statusItem.button {
			button.image = NSImage(named:NSImage.Name("StatusBarButtonImage"))
			if (button.image == nil) {
				print("Menubar button image is nil, falling back to using builtin image")
				// fall back to using a builtin icon, this should always work
				button.image = NSImage(named:NSImage.Name(NSImage.quickLookTemplateName))
				if (button.image == nil) {
					print("Menubar button image is *still* nil")
				}
			}
			button.toolTip="appFirewall ("+String(get_num_conns_blocked())+" blocked)"
			button.action = #selector(openapp(_:))
		} else {
			print("Problem getting menubar button, ", statusItem, statusItem.button ?? "nil")
		}*/
	
		// set default display state for GUI
		UserDefaults.standard.register(defaults: ["active_asc":true])
		UserDefaults.standard.register(defaults: ["blocklist_asc":true])
		UserDefaults.standard.register(defaults: ["log_asc":false])
		UserDefaults.standard.register(defaults: ["log_show_blocked":3])
					
		// set whether to use dtrace assistance or not
		UserDefaults.standard.register(defaults: ["dtrace": Config.enableDtrace])
		let sipEnabled = isSIPEnabled()
		print("SIP enabled: ",sipEnabled)
		var dtrace = UserDefaults.standard.integer(forKey: "dtrace")
		if (sipEnabled) { dtrace = 0 } // dtrace doesn't work with SIP
		if (dtrace > 0) {
			print("Dtrace enabled")
		} else {
			dtrace = 0
			print("Dtrace disabled")
		}
		// set whether Nstat assistance is used
		UserDefaults.standard.register(defaults: ["nstat": Config.enableNstat])
		let nstat = UserDefaults.standard.integer(forKey: "nstat")
		if (nstat>0) {
			print("Nstat enabled")
		} else {
			print("Nstat disabled")
		}
		
		// reload state
		load_state()
		Config.initLoad()
		
		// start listeners
		// this can be slow since it blocks while making network connection to helper
    DispatchQueue.global(qos: .background).async {
			start_helper_listeners(Int32(dtrace), Int32(nstat))
		}
		
		// schedule house-keeping ...
		timer = Timer.scheduledTimer(timeInterval: Config.appDelegateRefreshTime, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late
		timer_logs = Timer.scheduledTimer(timeInterval: Config.appDelegateFileRefreshTime, target: self, selector: #selector(refreshLogs), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late

		timer_stats = Timer.scheduledTimer(timeInterval: Config.appDelegateStatsRefreshTime, target: self, selector: #selector(stats), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late
		
		// setup handler for window close event
		print("mainWindow != nil: ",NSApp.mainWindow != nil)
		NSApp.mainWindow?.delegate = self
	}
	
	func applicationWillTerminate(_ aNotification: Notification) {
		print("stopping")
		// viewWillDisappear() event is triggered for any open windows
		// and will call save_state(), so no need to do it again here
		stop_helper_listeners()
		if (Config.getBlockQUIC()) { unblock_QUIC() }
		if (Config.getDnscrypt_proxy()) { stop_dnscrypt_proxy() }
	}
	
	func applicationDidEnterBackground(_ aNotification: Notification) {
		// Insert code here to tear down your application
		// NB: don't think this function is *ever* called
		print("going into background")
	}
	
	func applicationShouldHandleReopen(_ sender: NSApplication,
	hasVisibleWindows flag: Bool)->Bool {
		// called when click on dock icon to reopen window
		openapp(nil)
		return true
	}
}

extension AppDelegate: NSWindowDelegate {

	func windowWillClose(_ notification: Notification) {
		// hide the dock icon and main menu
		disableMenu()
	}
}
