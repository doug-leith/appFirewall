//
//  configData.swift
//  appFirewall
//
//  Created by Doug Leith on 04/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Foundation
import ServiceManagement

class Config: NSObject {
	// fixed settings ...
	static let defaultLoggingLevel = 2 // more verbose, for testing
	static let enableDtrace = 1 // disable for SIP testing
	static let enableUpdates = 1 // disable for testing
	
	static let minHelperVersion = 6 // required helper version, must be an Int
	
	static let crashURL = URL(string: "https://leith.ie/logcrash.php")!
	static let sampleURL = URL(string: "https://leith.ie/logsample.php")!
	static let updateCheckURL = URL(string: "https://github.com/doug-leith/appFirewall/raw/master/version")!
	static let updateURL = "https://github.com/doug-leith/appFirewall/raw/master/latest%20release/appFirewall.dmg"
	static let checkUpdatesInterval: Double = 2592000 // 30 days, in seconds !
	
	static let browsers = ["firefox","Google Chrome H","Safari","Opera Helper","Brave Browser H","seamonkey"]
	
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
		["Name": "Doug's Annoyances Block List","File": "dougs_blocklist.txt","URL": "https://www.scss.tcd.ie/doug.leith/dougs_blocklist.txt", "Tip": "Based on MAC OS application traffic.", "Type":"Blocklist"]
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
	static let viewRefreshTime : Double = 1 // check for window uodate every 1s

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
			UserDefaults.standard.set(date, forKey: "lastCheckUpdateDate")
			doCheckForUpdates(quiet: true, autoUpdate: autoUpdate)
		} else {
			print("doTimedCheckForUpdate, diff=",diff)
		}
	}
	
	static func initTimedCheckForUpdate() {
		UserDefaults.standard.register(defaults: ["autoCheckUpdates":true])
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
			let urls = LSCopyApplicationURLsForBundleIdentifier("com.leith.appFirewall-loginLaunch" as CFString, nil)?.takeRetainedValue() as NSArray?
			print("URLs for bundle identifier com.leith.appFirewall-loginLaunch:")
			for url in urls ?? [] {
				if let u = url as? URL {
					let b = Bundle(url: u)
					print(url, b?.infoDictionary?["CFBundleVersion"] as Any)
				}
			}
			SMLoginItemSetEnabled("com.leith.appFirewall-loginLaunch" as CFString, true)
		} else {
			SMLoginItemSetEnabled("com.leith.appFirewall-loginLaunch" as CFString, false)
		}
	}
	static func initLoad() {
		// called by app delegate at startup
		load_hostlists()
		initTimedCheckForUpdate()
		initRunAtLogin()
	}
	
	static func refresh() {
		// run after updating config
		initTimedCheckForUpdate()
		initRunAtLogin()
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

	static func getSetting(label: String, def: Bool)->Bool {
		UserDefaults.standard.register(defaults: [label: def])
		return UserDefaults.standard.bool(forKey: label)
	}
	
	static func getAutoCheckUpdates()->Bool {
		return getSetting(label: "autoCheckUpdates", def: true)
	}

	static func getAutoUpdate()->Bool {
		return getSetting(label: "autoUpdate", def: true)
	}

	static func getRunAtLogin()->Bool {
		return getSetting(label: "runAtLogin", def: false)
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
		// and wil default to above if not previously set
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
