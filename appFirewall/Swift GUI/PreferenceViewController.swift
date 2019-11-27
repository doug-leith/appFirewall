//
//  PreferenceViewController.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class PreferenceViewController: NSViewController {

	@IBOutlet weak var tableView: NSTableView!
	
	@IBOutlet weak var tableSelectedView: NSTableView!
	
	// available lists, hard-wired for now ...
	let HostNameLists : [[String: String]] =
	[
		["Name":"Energized Blu (Recommended)", "File": "energized_blu.txt", "URL": "https://block.energized.pro/blu/formats/hosts","Tip":"A large, quite complete list (231K entries).", "Type":"Hostlist"],
		["Name":"Steve Black Unified", "File": "steve_black_unified.txt", "URL": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts","Tip":"A good choice that tries to keep balance between blocking effectiveness and false positives.  Includes Dan Pollock's, MVPS, AdAway lists amongst other.  However, doesn't cover Irish specific trackers such as adservice.google.ie", "Type":"Hostlist"],
		["Name": "Goodbye Ads by Jerryn70 (Recommended)","File":"GoodbyeAds.txt",  "URL":"https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt","Tip":"Blocks mobile ads and trackers, including blocks ads by Facebook.  Includes Irish specific trackers such as adservice.google.ie", "Type":"Hostlist"],
		["Name": "Dan Pollock's hosts file","File": "hosts","URL":"https://someonewhocares.org/hosts/zero/hosts","Tip":"A balanced ad blocking hosts file.  Try this if other ones are blocking too much.", "Type":"Hostlist"],
		["Name": "AdAway","File":"hosts.txt","URL":"https://adaway.org/hosts.txt","Tip":"Blocks ads and some analytics but quite limited (only 525 hosts)", "Type":"Hostlist"],
		["Name": "hpHosts","File": "ad_servers.txt" ,"URL":"https://hosts-file.net/ad_servers.txt", "Tip":"Ad and trackers list from hpHosts, moderately sizesd (45K hosts)."],
		["Name": "Doug's Annoyances Block List","File": "dougs_blocklist.txt","URL": "https://www.scss.tcd.ie/doug.leith/dougs_blocklist.txt", "Tip": "Based on MAC OS application traffic.", "Type":"Blocklist"]
		//["Name": "","File": "","URL": "", "Tip": "", "Type":"Hostlist"]
	]

	var lists_lastUpdated : String = ""
	var EnabledLists : [String] = []
	var AvailableLists : [String] = []
	var changed : Bool = false
	var timer : Timer!
	var downloadsInProgess: Int = 0
	var downloadStartTime :  Double = 0

	
	override func viewDidLoad() {
		super.viewDidLoad()
		// Do view setup here.
		tableView.delegate = self
		tableView.dataSource = self
		tableSelectedView.delegate = self
		tableSelectedView.dataSource = self
		
		lists_lastUpdated = UserDefaults.standard.string(forKey: "lists_lastUpdated") ?? String("")
		refreshLabel.stringValue = "(Last updated:  "+lists_lastUpdated+")"
		timer = Timer.scheduledTimer(timeInterval: 1, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
	}
  
  func updateAvailableLists() {
		AvailableLists = []
		for item in HostNameLists{
			guard (item["Name"] != nil) else { continue };
			guard EnabledLists.firstIndex(of: item["Name"]!) == nil else { continue };
			AvailableLists.append(item["Name"]!);
		}
	}
	
	func load_hostlists() {
		// called by AppDelegate on application startup, and also by self
		// on changes to set of enabled lists
		
		// set default host list(s) to use
		UserDefaults.standard.register(defaults: [
			"host_lists":["Energized Blu (Recommended)"],
		])
		// reload enabled lists, persistent across runs of app
		// and wil default to above if not previously set
		EnabledLists = UserDefaults.standard.array(forKey: "host_lists") as? [String] ?? []
		updateAvailableLists()
		
		// update the host name files used, and reload,
		// we fall back to files distributed by app
		init_hosts_list();
		let filePath = String(cString:get_path())
		let backupPath = Bundle.main.resourcePath ?? "."
		var n = String("")
		for item in HostNameLists {
			guard (item["Name"] != nil) else { continue };
			guard EnabledLists.firstIndex(of: item["Name"]!) != nil else { continue };
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
			lists_lastUpdated = String(cString:get_file_modify_time(n))
			print("from file: last updated=",lists_lastUpdated)
			UserDefaults.standard.set(lists_lastUpdated, forKey: "lists_lastUpdated")
		}
	}
	
	override func viewWillDisappear() {
		// window is closing, save state
		super.viewWillDisappear()
		if (changed) {
			load_hostlists()
			changed = false
		}
		timer.invalidate()
	}

	@IBAction func AddButton(_ sender: Any) {
		let row = tableView.selectedRow
		if (row<0 || row > HostNameLists.count) { return }
		
		for item in EnabledLists {
			if (item == AvailableLists[row]) {
				// already enabled, ignore
				return
			}
		}
		EnabledLists.append(AvailableLists[row])
		UserDefaults.standard.set(EnabledLists, forKey: "host_lists")
		updateAvailableLists()
		tableSelectedView.reloadData()
		tableView.reloadData()
		changed = true
	}
	
	@IBAction func RemoveButton(_ sender: Any) {
		let row = tableSelectedView.selectedRow
		EnabledLists.remove(at: row)
		UserDefaults.standard.set(EnabledLists, forKey: "host_lists")
		updateAvailableLists()
		tableSelectedView.reloadData()
		tableView.reloadData()
		changed = true
	}
	
	@objc func refresh() {
		refreshLabel.stringValue = "(Last updated:  "+lists_lastUpdated+")"
		let elapsedTime = Date().timeIntervalSinceReferenceDate - downloadStartTime
		if ((downloadsInProgess == 0) || (elapsedTime>10.0)) {
			refreshButton?.isEnabled = true
		}
	}
	
	@IBOutlet weak var refreshLabel: NSTextField!
	
	@IBOutlet weak var refreshButton: NSButton!
	
	@IBAction func clickRefreshButton(_ sender: NSButton) {
	// TO DO: add better error reporting back to UI,
		// just now fails silently (into log)
		
		refreshButton.isEnabled = false
		downloadStartTime = Date().timeIntervalSinceReferenceDate
		for item in HostNameLists {
			let url_string = item["URL"] ?? ""
			if (url_string.count < 5) { continue; }
			let fname = item["File"] ?? ""
			if (fname.count == 0){ continue; }
			
			let url = URL(string: url_string)
			let s = URLSession(configuration: .default)
			let t = s.downloadTask(with: url!)
			{(urlOrNil, responseOrNil, errorOrNil) in
				// this is called when download completes
				self.downloadsInProgess -= 1
				guard let resp = responseOrNil else { return }
				if (errorOrNil != nil) {
					print("Problem downloading ", url_string, ": ",errorOrNil ?? "")
					return
				}
				let statusCode = (resp as! HTTPURLResponse).statusCode
				if (statusCode != 200) {
					print("Problem downloading ", url_string, ": ",statusCode);
					return
				}
				guard let fileURL = urlOrNil else { return }
				let path = String(cString:get_path())+fname
				do {
					try FileManager.default.removeItem(atPath: path+".0")
				} catch {}
				do {
					try FileManager.default.moveItem(atPath: path, toPath: path+".0")
				} catch {}
				do {
					try FileManager.default.moveItem(atPath: fileURL.path, toPath: path)
				} catch {
					print ("Error moving ",fileURL," to ",path,":", error)
				}
				self.lists_lastUpdated = String(cString:get_file_modify_time(path))
				UserDefaults.standard.set(self.lists_lastUpdated, forKey: "lists_lastUpdated")
				print("Successully downloaded ",url_string,", t=",self.lists_lastUpdated)
				}
			downloadsInProgess += 1
			t.resume() // start the download
		}
	}
}
	
extension PreferenceViewController: NSTableViewDataSource {
	func numberOfRows(in tView: NSTableView) -> Int {
		if (tView == tableView) {
			return AvailableLists.count
		} else {
			return EnabledLists.count
		}
	}
}

extension PreferenceViewController: NSTableViewDelegate {
	
	func tableView(_ tView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		if (tView == tableView) {
			let cellId = NSUserInterfaceItemIdentifier(rawValue: "HostListCell")
			
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {return nil}
			cell.textField?.stringValue = AvailableLists[row]
			var tip = ""
			for item in HostNameLists {
				if (item["Name"]! == AvailableLists[row]) {
						tip = item["Tip"] ?? ""
						tip += "\nURL:" + (item["URL"] ?? "")
						break
				}
			}
			cell.textField?.toolTip = tip

			return cell
		} else {
			let cellId = NSUserInterfaceItemIdentifier(rawValue: "EnabledListCell")
			
			guard let cell = tableSelectedView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {return nil}
			cell.textField?.stringValue = EnabledLists[row]
			var tip = ""
			for item in HostNameLists {
				if (item["Name"]! == EnabledLists[row]) {
							tip = item["Tip"] ?? ""
						tip += "\nURL:" + (item["URL"] ?? "")
					break
				}
			}
			cell.textField?.toolTip = tip

			return cell
		}
	}
}

