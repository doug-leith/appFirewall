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
	
	// timer for periodic polling ...
	var timer : Timer!
	// menubar button ...
	var statusItem = NSStatusBar.system.statusItem(withLength:NSStatusItem.squareLength)
	// create a preference pane instance
	let prefController : PreferenceViewController = NSStoryboard(name:"Main", bundle:nil).instantiateController(withIdentifier: "PreferenceViewController") as! PreferenceViewController
	
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
	
	func start_helper() {
		// install appFirewall-Helper if not already installed
		
		/*
		// clear defaults
		if let bundleID = Bundle.main.bundleIdentifier {
				UserDefaults.standard.removePersistentDomain(forName: bundleID)
		}*/
		
		let app_version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as! String
		let helper_version = UserDefaults.standard.string(forKey: "helper_version")
		os_log(.info, "app version %s, helper version %s", app_version, (helper_version ?? "-"))
		if (helper_version == app_version) {
			os_log(.info,"helper already installed")
			return // helper already installed
		}
		//return // for running daemon as normal process when testing
		
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
			//
 			// Call SMJobBless to verify appFirewall-Helper against the application
			// and vice-versa and, once verification has passed, to install the
			// helper.  The embedded launchd.plist
			// is extracted and placed in /Library/LaunchDaemons and then loaded. The
			// helper executable is placed in /Library/PrivilegedHelperTools.
			// See https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless
			let kHelperToolName:String = "com.leith.appFirewall-Helper"
			var cfError: Unmanaged<CFError>? = nil
			if !SMJobBless(kSMDomainSystemLaunchd, kHelperToolName as CFString, authRef, &cfError) {
				let blessError = cfError!.takeRetainedValue()
				exit_popup(msg:"Problem installing help: \(blessError), exiting.")

			}else{
				os_log(.info,"%s installed successfully",kHelperToolName)
				// and keep a record of fact that its installed so we don't keep
				// asking to reinstall it !
				UserDefaults.standard.set(app_version, forKey: "helper_version")
			}
		}
	}
	
	func make_data_dir() {
		// create ~/Library/Application Support/appFirewall directory if it doesn't
		// already exist
		let paths = NSSearchPathForDirectoriesInDomains(.applicationSupportDirectory, .userDomainMask, true);
		let appname = Bundle.main.infoDictionary!["CFBundleName"] as! String
		let path = paths[0]+"/"+appname
		if !FileManager.default.fileExists(atPath: path) {
				do {
						try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: nil)
						os_log(.info,"created %s", path)
				} catch {
						os_log(.info,"%s",error.localizedDescription);
				}
		}
		// and tell C helpers what the path we're using is
		set_path(path + "/")
		os_log(.info,"storage path %s",path + "/")
		
	}
	func applicationDidFinishLaunching(_ aNotification: Notification) {
		// Insert code here to initialize your application
				
		// install appFirewall-Helper, if not already installed
		start_helper()
		
		// reload state
		make_data_dir() // create storage dir if it doesn't already exist
		load_log()
		load_blocklist()
		load_dns_cache()
		prefController.load_hostlists()
		
		// set up handler to catch C errors
		setup_sigterm_handler()
		
		// start pcap listener 
		start_listener()
		
		// schedule house-keeping ...
		timer = Timer.scheduledTimer(timeInterval: 10, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late

		// setup menubar action
		if let button = statusItem.button {
			button.image = NSImage(named:NSImage.Name("StatusBarButtonImage"))
			button.toolTip="appFirewall"
			button.action = #selector(openapp(_:))
		}
	}
	
	func log_rotate() {
	// rotate human readable log file if getting too large
	let path = String(cString: get_path())
	let logfile = path + "/log.txt"
		do {
				let attr = try FileManager.default.attributesOfItem(atPath: logfile)
				let fileSize = attr[FileAttributeKey.size] as! UInt64
				//print("fileSize=",fileSize)
				if (fileSize > 100000000) { // 100M
						// rotate
						os_log(.info,"Rotating log")
						save_log() // this will flush human-readable log file
						try FileManager.default.removeItem(atPath:logfile+".0")
						try FileManager.default.moveItem(atPath:logfile, toPath: logfile+".0")
						load_log() // this we reopen human-readable log file
				}
		} catch {
				os_log(.info,"%s",error.localizedDescription);
		}

	}
	
	@objc func refresh() {
		// state is saved on window close, no need to do it here
		// (and if we do it here it might be interrupted by a windoe
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
	}

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
	
	func applicationWillTerminate(_ aNotification: Notification) {
		// Insert code here to tear down your application
		// NB: don't think this function is *ever* called
		print("stopping")
		stop_listener()
	}
	
	func applicationDidEnterBackground(_ aNotification: Notification) {
		// Insert code here to tear down your application
		// NB: don't think this function is *ever* called
		print("going into background")
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
		} else if (v.label == "Block List") {
			let c = v.viewController as! BlockListViewController
			c.copy(sender: nil)
		} else if (v.label == "Connection Log") {
			let c = v.viewController as! LogViewController
			c.copy(sender: nil)
		}
	}

	
}

