//
//  ActiveConnsViewController.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class ActiveConnsViewController: NSViewController {
	
	@IBOutlet weak var tableView: NSTableView!
	var timer : Timer!
	var asc: Bool = true // whether shown in ascending/descending order
		
	override func viewDidLoad() {
		// Do any additional setup after loading the view.
		super.viewDidLoad()
		tableView.delegate = self
		tableView.dataSource = self		
		start_pid_watcher() // start pid monitoring thread, its ok to call this multiple times
	}

	override func viewWillAppear() {
		// window is opening, populate it with content
		super.viewWillAppear()
		// restore to previous size
		self.view.window?.setFrameUsingName("connsView")
		// record active tab
		UserDefaults.standard.set(0, forKey: "tab_index")
		// enable click of column header to call sortDescriptorsDidChange action below
		asc = UserDefaults.standard.bool(forKey: "active_asc")
		if (tableView.tableColumns[0].sortDescriptorPrototype == nil) {
			tableView.tableColumns[0].sortDescriptorPrototype = NSSortDescriptor(key:"pid",ascending:asc)
			tableView.tableColumns[1].sortDescriptorPrototype = NSSortDescriptor(key:"domain",ascending:asc)
		}
		// schedule refresh of connections list every 1s
		timer = Timer.scheduledTimer(timeInterval: 1, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late
		refresh(timer:nil)
	}
		
	override func viewDidAppear() {
		super.viewDidAppear()
	}
	
	@objc func refresh(timer:Timer?) {
		var force : Bool = false;
		if (timer == nil) {
			force = true
		}
		let firstVisibleRow = tableView.rows(in: tableView.visibleRect).location
		//let changed = refresh_active_conns(0)
		if (force || ((firstVisibleRow==0) && (Int(get_pid_changed()) != 0)) ) {
			clear_pid_changed();
			tableView.reloadData()
		}
	}

	override func viewWillDisappear() {
		// window is closing, save state
		super.viewWillDisappear()
		save_log()
		save_blocklist(); save_whitelist()
		save_dns_cache()
		self.view.window?.saveFrame(usingName: "connsView") // record size of window
		timer.invalidate()
	}
	
	@IBAction func helpButton(_ sender: helpButton!) {
			sender.clickButton(msg:"This window logs the network connections currently being made by the apps running on your computer.  Note that connections can sometimes take a few seconds to die, during which time they may remain visible here.  Also, we only block connections when they try to start so its possible for some connections on the blacklist to be running temporarily, but they will be blocked when they try to restart.")
		}
	
	
	@IBAction func Click(_ sender: blButton!) {
		BlockBtnAction(sender: sender)
	}
	
	@objc func BlockBtnAction(sender : blButton!) {
		sender.clickButton()
		tableView.reloadData()
	}
}

extension ActiveConnsViewController: NSTableViewDataSource {
	func numberOfRows(in tableView: NSTableView) -> Int {
		return Int(get_num_conns())
	}
	
	func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
		guard let sortDescriptor = tableView.sortDescriptors.first else {
    return }
    asc = sortDescriptor.ascending
    UserDefaults.standard.set(asc, forKey: "active_asc")
		if (asc != oldDescriptors.first?.ascending) {
			tableView.reloadData()
		}
	}
}

extension ActiveConnsViewController: NSTableViewDelegate {

	func mapRow(row: Int) -> Int {
		//map from displayed row to row in PID list itself
		let last = Int(get_num_conns())-1
		if (row<0) { return 0 }
		if (row>last) { return last }
		if (asc) {
			return row
		} else {
			return last-row
		}
	}

	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		var cellIdentifier: String = ""
		var content: String = ""
		var tip: String = ""
	
		let r = mapRow(row: row)
		var item = get_conn(Int32(r))
		var bl_item = conn_to_bl_item(&item)
		let blocked = Int(blocked_status(&bl_item))
		let white = Int(is_white(&bl_item))

		if tableColumn == tableView.tableColumns[0] {
			cellIdentifier = "ProcessCell"
			content=String(cString: &item.name.0)
			tip = "PID: "+String(Int(item.pid))
		} else if tableColumn == tableView.tableColumns[1] {
			cellIdentifier = "ConnCell"
			let ip = String(cString: &item.dst_addr_name.0)
			var domain = String(cString: &bl_item.domain.0)
			if (domain.count == 0) {
				domain = ip
			} 
			let name = String(cString: &bl_item.name.0)
			let port = String(Int(item.raw.dport))
			if ((white == 1) || (blocked == 0)) {
				tip = "Domain "+domain+" ("+ip+":"+port+") is not blocked."
			} else if (blocked == 1) {
				tip = "Domain "+domain+" ("+ip+":"+port+") is blocked for application '"+name+"' by user black list."
				//print("active blocked conn:",String(cString: &item.name.0),":",domain,"/",ip)
			} else if (blocked == 2) {
				tip = "Domain "+domain+" ("+ip+":"+port+") is blocked for all applications by hosts file."
				//print("active blocked conn:",String(cString: &item.name.0),":",domain,"/",ip)
			} else {
				tip = "Domain "+domain+" ("+ip+":"+port+") is blocked for application '"+name+"' by hosts file."
				//print("active blocked conn:",String(cString: &item.name.0),":",domain,"/",ip)
			}
			content = domain
			if (Int(item.raw.udp)==1) {
				content = content + " (UDP/QUIC)"
			}
		} else if tableColumn == tableView.tableColumns[2] {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? blButton else {return nil}
			cell.udp = (Int(item.raw.udp)>0)
			cell.bl_item = bl_item // take a copy so ok to free() later
			cell.updateButton()
			cell.action = #selector(BlockBtnAction)
			return cell
		} else {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {return nil}
			cell.textField?.stringValue = content
			cell.textField?.toolTip = tip
			setColor(cell: cell, udp: (Int(item.raw.udp)==1), white: white, blocked: blocked)
			return cell
		}
	}
		
	func copy(sender: AnyObject?){
		let indexSet = tableView.selectedRowIndexes
		var text = ""
		for row in indexSet {
			let cell0 = tableView.view(atColumn:0, row:row,makeIfNecessary: true) as! NSTableCellView
			let str0 = cell0.textField?.stringValue ?? ""
			let cell1 = tableView.view(atColumn:1, row:row,makeIfNecessary: true) as! NSTableCellView
			let str1 = cell1.textField?.stringValue ?? ""
			text += str0+" "+str1+"\n"
		}
		let pasteBoard = NSPasteboard.general
		pasteBoard.clearContents()
		pasteBoard.setString(text, forType:NSPasteboard.PasteboardType.string)
	}
	
	func selectall(sender: AnyObject?){
		tableView.selectAll(nil)
	}
}

