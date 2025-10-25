//
//  configData.swift
//  appFirewall
//
//  Created by Doug Leith on 04/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Foundation
import ServiceManagement
import AppKit

func is_dnscrypt_running()->Bool {
	let pid_count = pgrep(Name : "dnscrypt-proxy")
	if (pid_count < 0) {
		print("WARNING: dnscrypt-proxy pgrep error.")
		return false // ?
	} else if (pid_count == 0) {
		//print("dnscrypt-proxy is not running.")
		return false
	} else {
		//print("dnscrypt-proxy is running.")
		return true
	}
}

class Config: NSObject {
	// fixed settings ...
	static let defaultLoggingLevel = 2 // more verbose, for testing
	static let enableDtrace = 0 // disable, replaced by nstat
	static let enableNstat = 0 // disable, replaced by pktap
	static let enableUpdates = 1 // disable for testing
	static let enableConsentForm = 0 // disabled
	static let testFirst = false // enable for testing first run behaviour
	static let testUpdates = false // enable for testing download of updates
	static let testSample = false // enable for testing upload of app sample

	static let minHelperVersion = 15 // required helper version, must be an Int
	
	static let crashURL = URL(string: "https://leith.ie/logcrash.php")!
	static let sampleURL = URL(string: "https://leith.ie/logsample.php")!
	static let firstSampleInterval: Double = 86400 // 1 day, in seconds !
	static let firstSampleNum = 7 // sample daily for first week, then monthly
	static let sampleInterval: Double = 2592000 // 30 days, in seconds !
	static let updateCheckURL = URL(string: "https://github.com/doug-leith/appFirewall/raw/master/version")!
	static let updateURL = "https://github.com/doug-leith/appFirewall/raw/master/latest%20release/appFirewall.dmg"
	static let checkUpdatesInterval: Double = 2592000 // 30 days, in seconds !
	
	static let browsers = ["firefox","Google Chrome H","Safari","com.apple.Safar","Opera Helper","Brave Browser H","seamonkey","com.apple.WebKi", "Microsoft Edge","Yandex Helper"]
	
	static let csrutil = "/usr/bin/csrutil"
	static let pgrep = "/usr/bin/pgrep"
	
	static let defaultNameList = ["host_lists":["Energized Blu (Recommended)"],]
	static let hostNameLists : [[String: String]] =
	[
		["Name":"Energized Blu (Recommended)", "File": "energized_blu.txt", "URL": "https://block.energized.pro/blu/formats/hosts","Tip":"A large, quite complete list (231K entries).", "Type":"Hostlist"],
		["Name":"Steve Black Unified", "File": "steve_black_unified.txt", "URL": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts","Tip":"A good choice that tries to keep balance between blocking effectiveness and false positives.  Includes Dan Pollock's, MVPS, AdAway lists amongst other.  However, doesn't cover Irish specific trackers such as adservice.google.ie", "Type":"Hostlist"],
		["Name": "Goodbye Ads by Jerryn70","File":"GoodbyeAds.txt",  "URL":"https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt","Tip":"Blocks mobile ads and trackers, including blocks ads by Facebook.  Includes Irish specific trackers such as adservice.google.ie", "Type":"Hostlist"],
		["Name": "Dan Pollock's hosts file","File": "hosts","URL":"https://someonewhocares.org/hosts/zero/hosts","Tip":"A balanced ad blocking hosts file.  Try this if other ones are blocking too much.", "Type":"Hostlist"],
		["Name": "AdAway","File":"hosts.txt","URL":"https://adaway.org/hosts.txt","Tip":"Blocks ads and some analytics but quite limited (only 525 hosts)", "Type":"Hostlist"],
		["Name": "hpHosts","File": "ad_servers.txt" ,"URL":"https://hosts-file.net/ad_servers.txt", "Tip":"Ad and trackers list from hpHosts, moderately sizesd (45K hosts)."],
		["Name": "Doug's Annoyances Block List","File": "dougs_blocklist.txt","URL": "https://github.com/doug-leith/appFirewall/raw/master/appFirewall/BlackLists/dougs_blocklist.txt", "Tip": "Based on MAC OS application traffic.", "Type":"Blocklist"]
		//["Name": "","File": "","URL": "", "Tip": "", "Type":"Hostlist"]
	]
	
	static let logName = "log.dat"
	static let logTxtName = "log.txt" // human readable log file
	static let appLogName = "app_log.txt"
	static let dnsName = "dns.dat"
	static let blockListName = "blocklist.dat"
	static let whiteListName = "whitelist.dat"
	static let dnsConnListName = "dns_connlist.dat"
	
	static let appDelegateRefreshTime : Double = 10 // check state every 10s
	static let appDelegateFileRefreshTime : Double = 300 // save log every 5min
	static let appDelegateStatsRefreshTime : Double = 600 // print stats every 10min
	static let viewRefreshTime : Double = 1 // check for window update every 1s
	static let settingsRefreshTime : Double = 5 // check settings

	//------------------------------------------------
	// settings that can be changed by user ...
	static var checkUpdateTimer : Timer = Timer() // timer for updates
	static var EnabledLists : [String] = []
	static var AvailableLists : [String] = []

	@objc static func doTimedCheckForUpdate() {
		// used for timed update checking
		print("doTimedCheckForUpdate")
		var date = UserDefaults.standard.object(forKey: "lastCheckUpdateDate") as? NSDate
		if (date == nil) { // first time checking for updates
			date = NSDate()
			UserDefaults.standard.set(date, forKey: "lastCheckUpdateDate")
		}
		guard let diff = date?.timeIntervalSinceNow else { print("Problem getting date diff when checking for updates"); return } // shouldn't happen
		if (diff < -checkUpdatesInterval) {
			// time since last check for updates exceeds checkUpdatesInterval
			print("doTimedCheckForUpdate, diff=",diff,": doing update check")
			UserDefaults.standard.register(defaults: ["autoUpdate":true])
			let autoUpdate = UserDefaults.standard.bool(forKey: "autoUpdate")
			UserDefaults.standard.set(NSDate(), forKey: "lastCheckUpdateDate")
			doCheckForUpdates(quiet: true, autoUpdate: autoUpdate)
		} else {
			print("doTimedCheckForUpdate, diff=",diff)
		}
	}
	
	static func initTimedCheckForUpdate() {
		UserDefaults.standard.register(defaults: ["autoCheckUpdates":false])
		print("initTimedCheckForUpdate: autoCheckUpdates ",UserDefaults.standard.bool(forKey: "autoCheckUpdates"))
		if UserDefaults.standard.bool(forKey: "autoCheckUpdates") {
			// we periodically check to see if we need to
			// check for updates.  do it this way as its sure to work even
			// if app has been closed for a while - not sure Timer() class
			// will do the right thing, and apple documentation is rubbish as
			// usual
			checkUpdateTimer = Timer.scheduledTimer(timeInterval: 3600, target: self, selector: #selector(doTimedCheckForUpdate), userInfo: nil, repeats: true)
		} else {
			checkUpdateTimer.invalidate()
		}
	}

	static func initRunAtLogin() {
		print("run at login: ", getRunAtLogin())
		// command to list all programs with same bundle identifier:
		// mdfind kMDItemCFBundleIdentifier == com.leith.appFirewall-loginLaunch
		if getRunAtLogin() {
			let urls = LSCopyApplicationURLsForBundleIdentifier("com.leith.appFirewall-loginLaunch" as CFString, nil)?.takeRetainedValue() as? [URL]
			print("URLs for bundle identifier com.leith.appFirewall-loginLaunch:")
			for url in urls ?? [] {
				let b = Bundle(url: url)
				print(url, b?.infoDictionary?["CFBundleVersion"] as Any)
			}
			SMLoginItemSetEnabled("com.leith.appFirewall-loginLaunch" as CFString, true)
		} else {
			SMLoginItemSetEnabled("com.leith.appFirewall-loginLaunch" as CFString, false)
		}
	}
	
	static func initMenuBar() {
		// setup menubar action
		guard let delegate = NSApp.delegate as? AppDelegate else { print("WARNING: Problem getting delegatre in Config.initMenuBar"); useMenuBar(value:false); return}

		if (getUseMenuBar() == false) {
			delegate.statusItem.isVisible = false
			return
		} else {
			delegate.statusItem.isVisible = true
			let val = UserDefaults.standard.integer(forKey: "Number of connections blocked")
			set_num_conns_blocked(Int32(val))
			if let button = delegate.statusItem.button {
				button.image = NSImage(named:NSImage.Name("StatusBarButtonImage"))
				if (button.image == nil) {
					print("WARNING: Menubar button image is nil, falling back to using builtin image")
					// fall back to using a builtin icon, this should always work
					button.image = NSImage(named:NSImage.Name(NSImage.quickLookTemplateName))
					if (button.image == nil) {
						print("WARNING: Menubar button image is *still* nil, disabling button")
						delegate.statusItem.isVisible = false
						useMenuBar(value:false) // disable menubar
						DispatchQueue.main.async { error_popup(msg:"Problem getting menubar button, disabling button") }
					}
				}
				button.toolTip="appFirewall ("+String(get_num_conns_blocked())+" blocked)"
				button.action = #selector(delegate.openapp(_:))
			} else {
				print("WARNING: Problem getting menubar button, disabling button: ", delegate.statusItem, delegate.statusItem.button ?? "nil")
				delegate.statusItem.isVisible = false
				useMenuBar(value:false) // disable menubar
				DispatchQueue.main.async { error_popup(msg:"Problem getting menubar button, disabling button") }
			}
		}
	}
	
	static func checkBlockQUIC_status() {
		// confirm actual firewall status matches our settings
		let blocked = QUIC_status()
		if  (blocked==1) && (!getBlockQUIC()) {
			print("WARNING: QUIC blocked when it should be unblocked")
			blockQUIC(value:true)
		} else if (blocked==0) && getBlockQUIC() {
			print("WARNING: QUIC not blocked when it should be.")
			blockQUIC(value:false)
		}
	}
	
	static func initBlockQUIC() {
		if (getBlockQUIC() == false) {
			if let msg_ptr = unblock_QUIC() {
				print("WARNING: Problem trying to unblock QUIC")
				let helper_msg = String(cString: msg_ptr);
				let msg = "Problem trying to unblock QUIC ("+helper_msg+")"
				DispatchQueue.main.async { error_popup(msg:msg) }
				// should we blockQUIC(value:true) since it might still be enabled ?
			}
		} else {
			if let msg_ptr = block_QUIC()  {
				print("WARNING: Problem trying to block QUIC")
				let helper_msg = String(cString: msg_ptr);
				let msg = "Problem trying to block QUIC ("+helper_msg+")"
				DispatchQueue.main.async { error_popup(msg:msg) }
				blockQUIC(value:false)
			}
		}
		checkBlockQUIC_status()
	}
	
	static func checkDnscrypt_proxy_status() {
		// align our setting with actual status ...
		// wait up to 250ms for dnscrypt-proxy status to update.
		// this check can be unreliable -- might be in the process of
		// stopping but pgrep status hasn't changed to reflect this,
		// usleep() helps
		/*var running = is_dnscrypt_running()
		var stopping = running && (!getDnscrypt_proxy())
		var starting = !running && getDnscrypt_proxy()
		var count : Int = 0
		while ((starting || stopping) && (count<5)) {
			usleep(50000) // 50ms
			running = is_dnscrypt_running()
			stopping = running && (!getDnscrypt_proxy())
			starting = !running && getDnscrypt_proxy()
			count = count + 1
		}*/
		
		// let's also ask helper what it thinks dns server status is
		var dnscrypt_proxy_stopped: Int32 = 0
		var dnscrypt_proxy_running: Int32 = 0
		var line = String(cString:GetDNSOutput(&dnscrypt_proxy_stopped, &dnscrypt_proxy_running))
		var stopping = (dnscrypt_proxy_stopped==0) && (!getDnscrypt_proxy())
		var starting = (dnscrypt_proxy_stopped==1) && getDnscrypt_proxy()
		var count : Int = 0
		while ((starting || stopping) && (count<5)) {
			usleep(50000) // 50ms
			line = String(cString:GetDNSOutput(&dnscrypt_proxy_stopped, &dnscrypt_proxy_running))
			stopping = (dnscrypt_proxy_stopped==0) && (!getDnscrypt_proxy())
			starting = (dnscrypt_proxy_stopped==1) && getDnscrypt_proxy()
			count = count + 1
		}
		if (stopping) {
			print("WARNING: dnscrypt running when it should be stopped")
			if (dnscrypt_proxy_running == 0)  {
				// helper thinks dns server should be stopped, good.
				if (dnscrypt_proxy_stopped == 0)  {
					// might still be in process of stopping though.
				} else {
					// helper thinks server is stopped and so do we, but pgrep says otherwise
					//dnscrypt_proxy(value:true)
					DispatchQueue.main.async {
						error_popup(msg:"DNS-over-HTTS server hasn't stopped yet, although helper thinks it should have.")
					}
				}
			} else {
				// helper thinks dns server should be running, but we think it
				// should be stopped.  likely an error.
				// update our state to match that of helper ...
				// and warn user of fishy behaviour
				dnscrypt_proxy(value:true)
				DispatchQueue.main.async {
					error_popup(msg:"DNS-over-HTTS server hasn't stopped yet.")
				}
			}
		} else if (starting) {
			print("WARNING: dnscrypt is not running when it should be.")
			if (dnscrypt_proxy_running == 1)  {
				// helper thinks dns server should be started, good.
				if (dnscrypt_proxy_stopped == 0)  {
					// could just be slow to start.
				} else {
					// shouldn't happen.
					print("ERROR: dnscrypt_proxy_running == 1 and dnscrypt_proxy_stopped == 1 in initDnscrypt_proxy()")
				}
			} else {
				// pgrep says dns server not started, and flag within helper
				// also says not active.  yet we think it should be, so
				// something has gone wrong.
				// update our state to match helpers ...
				// and warn user
				dnscrypt_proxy(value:false)
				DispatchQueue.main.async {
					error_popup(msg:"DNS-over-HTTS server stopped unexpectedly: "+line)
				}
			}
		}
	}
	
	static func initDnscrypt_proxy() {		
		if (getDnscrypt_proxy() == false) {
			if let msg_ptr = stop_dnscrypt_proxy() {
				print("WARNING: Problem trying to stop dnscrypt-proxy")
				let helper_msg = String(cString: msg_ptr);
				let msg = "Problem trying to stop DNS server ("+helper_msg+")"
				DispatchQueue.main.async { error_popup(msg:msg) }
			}
		} else {
			if let msg_ptr = start_dnscrypt_proxy(Bundle.main.bundlePath+"/Contents") {
				print("WARNING: Problem trying to start dnscrypt-proxy")
				dnscrypt_proxy(value:false)
				let helper_msg = String(cString: msg_ptr);
				let msg = "Problem trying to start DNS server ("+helper_msg+")"
				DispatchQueue.main.async { error_popup(msg:msg) }
			}
		}
		checkDnscrypt_proxy_status()
	}
	
	static func initLoad() {
		// called by app delegate at startup
		initMenuBar() // must be done on main thread
		DispatchQueue.global(qos: .background).async {
			load_hostlists()
			initTimedCheckForUpdate()
			initRunAtLogin()
			initBlockQUIC()
			initDnscrypt_proxy()
		}
	}
	
	enum options {
		case menuBar, timedCheckForUpdate,runAtLogin,blockQUIC,dnscrypt_proxy
	}
	static func refresh(opts: Set<options>) {
		// run after updating config
		if (opts.contains(.menuBar)) { initMenuBar() }
		if (opts.contains(.timedCheckForUpdate)) { initTimedCheckForUpdate() }
		if (opts.contains(.runAtLogin)) { initRunAtLogin() }
		if (opts.contains(.blockQUIC)) { initBlockQUIC() }
		if (opts.contains(.dnscrypt_proxy)) { initDnscrypt_proxy() }
	}
	
	static func autoCheckUpdates(value: Bool) {
		UserDefaults.standard.set(value, forKey: "autoCheckUpdates")
	}
	
	static func autoUpdate(value: Bool) {
		UserDefaults.standard.set(value, forKey: "autoUpdate")
	}
	
	static func runAtLogin(value: Bool) {
		UserDefaults.standard.set(value, forKey: "runAtLogin")
	}
	
	static func useMenuBar(value: Bool) {
		UserDefaults.standard.set(value, forKey: "useMenuBar")
	}

	static func blockQUIC(value: Bool) {
		UserDefaults.standard.set(value, forKey: "blockQUIC")
	}
	
	static func dnscrypt_proxy(value: Bool) {
		UserDefaults.standard.set(value, forKey: "dnscrypt_proxy")
	}

	static func getSetting(label: String, def: Bool)->Bool {
		UserDefaults.standard.register(defaults: [label: def])
		return UserDefaults.standard.bool(forKey: label)
	}
	
	static func getAutoCheckUpdates()->Bool {
		return getSetting(label: "autoCheckUpdates", def: false)
	}

	static func getAutoUpdate()->Bool {
		return getSetting(label: "autoUpdate", def: true)
	}

	static func getRunAtLogin()->Bool {
		return getSetting(label: "runAtLogin", def: false)
	}

	static func getUseMenuBar()->Bool {
		return getSetting(label: "useMenuBar", def: true)
	}

	static func getBlockQUIC()->Bool {
		return getSetting(label: "blockQUIC", def: false)
	}
	
	static func getDnscrypt_proxy()->Bool {
		return getSetting(label: "dnscrypt_proxy", def: false)
	}

  static func updateAvailableLists() {
  	// called after changing EnabledLists
		UserDefaults.standard.set(Config.EnabledLists, forKey: "host_lists")
		AvailableLists = []
		for item in Config.hostNameLists{
			guard let n = item["Name"] else { print("WARNING: problem in Config empty name in host list on update"); continue };
			guard EnabledLists.firstIndex(of: n) == nil else { continue }
			AvailableLists.append(n);
		}
	}
	
	static func getListsLastUpdated()->String {
		return UserDefaults.standard.string(forKey: "lists_lastUpdated") ?? ""
	}
	
	static func listsLastUpdated(value:String) {
		UserDefaults.standard.set(value, forKey: "lists_lastUpdated")
	}
	
	static func load_hostlists() {
		// set default host list(s) to use
		UserDefaults.standard.register(defaults: Config.defaultNameList)
		// reload enabled lists, persistent across runs of app
		// and will default to above if not previously set
		EnabledLists = UserDefaults.standard.array(forKey: "host_lists") as? [String] ?? []
		updateAvailableLists()
		
		// update the host name files used, and reload,
		// we fall back to files distributed by app
		init_hosts_list() // initialise C helpers
		let filePath = String(cString:get_path())
		let backupPath = Bundle.main.resourcePath ?? "./"
		var n = String("")
		for item in Config.hostNameLists {
			guard let nn = item["Name"] else { print("WARNING: problem in Config empty name in host list");  continue };
			guard EnabledLists.firstIndex(of: nn) != nil else { continue };
			guard let fname = item["File"] else { continue };
			print("adding ", filePath+fname)
			if (item["Type"]=="Hostlist") {
				// read in file and adds to hosts list table
				n=filePath+fname
				if (load_hostsfile(n)<0) {
					n=backupPath+"/BlackLists/"+fname
					print("Falling back to loading from ",n)
					load_hostsfile(n)
				}
			} else if (item["Type"]=="Blocklist") {
				// read in file and adds to hosts list table
				n=filePath+fname
				if (load_blocklistfile(n)<0){
					n=backupPath+"/BlackLists/"+fname
					print("Falling back to loading from ",n)
					load_blocklistfile(n)
				}
			}
			let lists_lastUpdated = String(cString:get_file_modify_time(n))
			print("from file: last updated=",lists_lastUpdated)
			listsLastUpdated(value:lists_lastUpdated)
		}
	}
}
