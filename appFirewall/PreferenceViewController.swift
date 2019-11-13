//
//  PreferenceViewController.swift
//  appFirewall
//

import Cocoa

class PreferenceViewController: NSViewController {

	@IBOutlet weak var tableView: NSTableView!
	
	@IBOutlet weak var tableSelectedView: NSTableView!
	
	// available lists, hard-wired for now ...
	let HostNameLists : [[String: String]] =
	[
		["Name":"Energized Blu", "File": "energized_blu.txt", "URL": "https://block.energized.pro/blu/formats/hosts","Tip":"A large, quite complete list (231K entries)."],
		["Name":"Steve Black Unified", "File": "steve_black_unified.txt", "URL": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts","Tip":"A good choice that tries to keep balance between blocking effectiveness and false positives.  Includes Dan Pollock's, MVPS, AdAway lists amongst other.  However, doesn't cover Irish specific trackers such as adservice.google.ie"],
		["Name": "Goodbye Ads by Jerryn70 (Recommended)","File":"GoodbyeAds.txt",  "URL":"https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt","Tip":"Blocks mobile ads and trackers, including blocks ads by Facebook.  Includes Irish specific trackers such as adservice.google.ie"],
		["Name": "Dan Pollock's hosts file","File": "hosts","URL":"http://someonewhocares.org/hosts/zero/hosts","Tip":"A balanced ad blocking hosts file.  Try this if other ones are blocking too much."],
		["Name": "AdAway","File":"hosts.txt","URL":"https://adaway.org/hosts.txt","Tip":"Blocks ads and some analytics but quite limited (only 525 hosts)"],
		["Name": "hpHosts","File": "ad_servers.txt" ,"URL":"http://hosts-file.net/ad_servers.txt", "Tip":"Ad and trackers list from hpHosts, moderately sizesd (45K hosts)."],
		["Name": "Doug's List","File": "dougs_list.txt","URL": "", "Tip": "Based on MAC OS application traffic."]
		//["Name": "","File": "","URL": "", "Tip": ""]
	]
	
	var EnabledLists : [String] = []
	var AvailableLists : [String] = []
	var changed : Bool = false
	
	override func viewDidLoad() {
		super.viewDidLoad()
		// Do view setup here.
		tableView.delegate = self
		tableView.dataSource = self
		tableSelectedView.delegate = self
		tableSelectedView.dataSource = self
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
			"host_lists":["Goodbye Ads by Jerryn70 (Recommended)"],
		])
		// reload enabled lists, persistent across runs of app
		// and wil default to above if not previously set
		EnabledLists = UserDefaults.standard.array(forKey: "host_lists") as? [String] ?? []
		updateAvailableLists()
		
		// update the host name files used, and reload
		init_hosts_list();
		let filePath = Bundle.main.resourcePath ?? "."
		for item in HostNameLists {
			guard (item["Name"] != nil) else { continue };
			guard EnabledLists.firstIndex(of: item["Name"]!) != nil else { continue };
			guard let fname = item["File"] else { continue };
			print("adding ", filePath+"/BlackLists/"+fname)
			load_hostsfile(filePath+"/BlackLists/"+fname); // reads in file and adds to hosts list table
		}
	}
	
	override func viewWillDisappear() {
		// window is closing, save state
		super.viewWillDisappear()
		if (changed) {
			load_hostlists()
			changed = false
		}
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

