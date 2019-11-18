//
//  AppDelegate.swift
//  appFirewall
//
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
	// handlers for management of appFirewall-Helper process
	func is_helper_running(Name: String)->Bool {
		// is helper binary there ?
		let path = "/Library/PrivilegedHelperTools/"+Name
		if !FileManager.default.fileExists(atPath: path) {
			print("helper binary not found at "+path)
			return false
		}
		
		// is it running ?
		let task = Process();
		task.launchPath = "/usr/bin/pgrep"
		task.arguments = [Name]
		let pipe = Pipe()
		task.standardOutput = pipe
		task.launch()
		let resp = pipe.fileHandleForReading.readDataToEndOfFile()
		task.waitUntilExit()
		let pid_str = (String(data: resp, encoding: .utf8) ?? "-1").trimmingCharacters(in: .whitespacesAndNewlines)
		if (resp.count == 0) {
			print("helper binary not running, null pgrep output")
			return false
		}
		let pid = Int(pid_str) ?? -1
		if (pid  < 0) {
			print("helper binary not running, pgrep output not an int")
			return false
		}
		print("helper binary installed and running")
		return true
	}
	
	func get_helper_version(Name: String)->Int {
		// we extract this from the helper Info.plist
		let path = "/Library/LaunchDaemons/"+Name+".plist"
		if let dict = NSDictionary(contentsOfFile: path) as? Dictionary<String, AnyObject> {
				//print(dict)
				guard let version:Int = dict["Version"] as? Int else {return -1}
				print(String(format:"helper version is %d",version))
				return version
		} else {
			print("problem reading helper version from "+path)
			return -1
		}
	}
	
	func start_helper() {
		// install appFirewall-Helper if not already installed
		
		/*
		// clear defaults
		if let bundleID = Bundle.main.bundleIdentifier {
				UserDefaults.standard.removePersistentDomain(forName: bundleID)
		}*/
		
		/*let app_version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as! String
			let helper_version = UserDefaults.standard.string(forKey: "helper_version")
		*/
		let kHelperToolName:String = "com.leith.appFirewall-Helper"

		let REQUIRED_VERSION = 1
		if (is_helper_running(Name: kHelperToolName)) {
			let version = get_helper_version(Name: kHelperToolName)
			if (version == REQUIRED_VERSION) {
				print(String(format:"helper "+kHelperToolName+", version %d already installed.", version))
				return // right version of helper already installed
			}
		}
		
		// ask user for authorisation to install helper
		var authRef:AuthorizationRef?
		let authItem = AuthorizationItem(name: kSMRightBlessPrivilegedHelper,valueLength: 0, value:UnsafeMutableRawPointer(bitPattern: 0), flags: 0)
		var authItems = [authItem]
		var authRights:AuthorizationRights = AuthorizationRights(count: UInt32(authItems.count), items:&authItems)
		let authFlags: AuthorizationFlags = [
			[],
			.extendRights,
			.interactionAllowed,
			.preAuthorize
		]
		let status = AuthorizationCreate(&authRights, nil, authFlags, &authRef)
		if (status != errAuthorizationSuccess){
			let error = NSError(domain:NSOSStatusErrorDomain, code:Int(status), userInfo:nil)
			exit_popup(msg:"Authorization error: \(error)")
		}else{
			// We have authorisation from user, go ahead and install helper
 			// Call SMJobBless to verify appFirewall-Helper and,
			// once verification has passed, to install the
			// helper.  The embedded launchd.plist
			// is extracted and placed in /Library/LaunchDaemons and then loaded.
			// The helper executable is placed in /Library/PrivilegedHelperTools.
			// See https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless
			var cfError: Unmanaged<CFError>? = nil
			if !SMJobBless(kSMDomainSystemLaunchd, kHelperToolName as CFString, authRef, &cfError) {
				let blessError = cfError!.takeRetainedValue()
				exit_popup(msg:"Problem installing helper: \(blessError), exiting.")
			}else{
				print(kHelperToolName+" installed successfully")
			}
		}
	}
	
	//--------------------------------------------------------
	// C helpers
	func setup_sigterm_handler() {
		// if a C routine fatally fails it raises a SIGCHLD signal
		// and we catch it here to raise an popup to inform user
		// and exit gracefully
		let handler: @convention(c) (Int32) -> () = { sig in
			// handle the signal
			exit_popup(msg:String(cString: get_error_msg()))
		}
		var action = sigaction(__sigaction_u: unsafeBitCast(handler, to: __sigaction_u.self),
													sa_mask: 0,
													sa_flags: 0)
		sigaction(SIGCHLD, &action, nil)
	}
	
	func make_data_dir() {
		// create ~/Library/Application Support/appFirewall directory if
		// it doesn't already exist, and pass path on to C routines
		let paths = NSSearchPathForDirectoriesInDomains(.applicationSupportDirectory, .userDomainMask, true);
		let appname = Bundle.main.infoDictionary!["CFBundleName"] as! String
		let path = paths[0]+"/"+appname
		if !FileManager.default.fileExists(atPath: path) {
				do {
						try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: nil)
						print("created "+path)
				} catch {
						print("problem making data_dir: "+error.localizedDescription);
				}
		}
		// and tell C helpers what the path we're using is
		set_path(path + "/")
		print("storage path "+path)
	}
	
	func log_rotate() {
	// rotate human readable log file if getting too large
	let path = String(cString: get_path())
	let logfile = path + "/log.txt"
		do {
				let attr = try FileManager.default.attributesOfItem(atPath: logfile)
				let fileSize = attr[FileAttributeKey.size] as! UInt64
				if (fileSize > 100000000) { // 100M
						// rotate
						print("Rotating log")
						save_log() // this will flush human-readable log file
						try FileManager.default.removeItem(atPath:logfile+".0")
						try FileManager.default.moveItem(atPath:logfile, toPath: logfile+".0")
						load_log() // this we reopen human-readable log file
				}
		} catch {
				print("Problem rotating log: "+error.localizedDescription)
		}

	}
	
	@objc func refresh() {
		// note: state is saved on window close, no need to do it here
		// (and if we do it here it might be interrupted by a window
		// close event and lead to file corruption
		//save_log()
		//save_blocklist()
		//save_dns_cache()
		
		// check is listener thread (for talking with helper process that
		// has root priviledge) has run into trouble -- if so, its fatal
		if (Int(listener_error()) != 0) {
				raise(SIGCHLD)
		}
		// rotate log files if they're getting too large
		log_rotate()
		
		// update menubar button tooltip
		if let button = statusItem.button {
			button.toolTip="appFirewall ("+String(get_num_conns_blocked())+" blocked)"
		}
		UserDefaults.standard.set(Int(get_num_conns_blocked()), forKey: "Number of connections blocked")
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
		
		// set default sorting state for GUI
		UserDefaults.standard.register(defaults: ["active_asc":true])
		UserDefaults.standard.register(defaults: ["blocklist_asc":true])
		UserDefaults.standard.register(defaults: ["log_asc":false])

		// set up handler to catch C errors
		setup_sigterm_handler()
		
		// reload state
		load_log()
		load_blocklist()
		load_whitelist()
		load_dns_cache()
		prefController.load_hostlists() // might be slow
		init_pid_list()
		//print(String(Double(DispatchTime.now().uptimeNanoseconds)/1.0e9),"files loaded in applicationWillFinishLaunching()")

		// start listeners
		// this can be slow since it blocks while making network connection to helper
    DispatchQueue.global(qos: .background).async {
			print(String(Double(DispatchTime.now().uptimeNanoseconds)/1.0e9),"starting listeners")
			start_helper_listeners()
			print(String(Double(DispatchTime.now().uptimeNanoseconds)/1.0e9),"listeners started")
		}
		
		// schedule house-keeping ...
		timer = Timer.scheduledTimer(timeInterval: 10, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
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

