//
//  LogViewController.swift
//  appFirewall
//


import Cocoa

class LogViewController: NSViewController {
	
	@IBOutlet weak var tableView: NSTableView!
	var timer : Timer!
	@IBOutlet weak var searchField: NSSearchField!
	@IBOutlet weak var showBlockedButton: NSButton!
	var asc: Bool = false // whether log is shown in ascending/descending order
	var show_blocked: Int = 3

	@IBOutlet weak var tableHeader: NSTableHeaderView!

	@IBOutlet weak var ConnsColumn: NSTableColumn!
	
	override func viewDidLoad() {
		super.viewDidLoad()
		tableView.delegate = self
		tableView.dataSource = self

		// schedule refresh of connections list every 1s
		timer = Timer.scheduledTimer(timeInterval: 2, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late
	}
	
	override func viewWillAppear() {
		super.viewWillAppear()
		self.view.window?.setFrameUsingName("connsView") // restore to previous size
		UserDefaults.standard.set(1, forKey: "tab_index") // record active tab
		
		// enable click of column header to call sortDescriptorsDidChange action below
		asc = UserDefaults.standard.bool(forKey: "log_asc")
		if (tableView.tableColumns[0].sortDescriptorPrototype==nil) {
			tableView.tableColumns[0].sortDescriptorPrototype = NSSortDescriptor(key:"time",ascending:asc)
			tableView.tableColumns[1].sortDescriptorPrototype = NSSortDescriptor(key:"conn",ascending:asc)
		}
	
		show_blocked = UserDefaults.standard.integer(forKey: "log_show_blocked")
		if (show_blocked == 0) {
			showBlockedButton.state = .off
		} else {
			showBlockedButton.state = .on
		}
		
		ConnsColumn.headerCell.title="Connections ("+String(Int(get_num_conns_blocked()))+" blocked)"
		
		refresh(timer: nil) // refresh the table when it is redisplayed
	}
	
	@objc func refresh(timer:Timer?) {
		var force : Bool = true
		if (timer != nil) {
			force = false
		}
		let firstVisibleRow = tableView.rows(in: tableView.visibleRect).location
		//print("log refresh first=",firstVisibleRow," changed=",has_log_changed())
		if (force || (has_log_changed() == 2) // force or log cleared
			  || ((firstVisibleRow==0) && (has_log_changed() != 0)) ) {
			clear_log_changed()
			filter_log_list(Int32(show_blocked),searchField.stringValue)
			tableView.reloadData()
		} else if (has_log_changed() == 1){
			// update scrollbars but leave rest of view alone
			tableView.noteNumberOfRowsChanged()
		}
		ConnsColumn.headerCell.title="Connections ("+String(Int(get_num_conns_blocked()))+" blocked)"
	}

	override func viewWillDisappear() {
		super.viewWillDisappear()
		//print("saving state")
		save_log()
		save_blocklist(); save_whitelist()
		save_dns_cache()
		self.view.window?.saveFrame(usingName: "connsView") // record size of window
	}
	
	
	@IBAction func helpButton(_ sender: helpButton!) {
			sender.clickButton(msg:"This window logs the network connections made by the apps running on your computer.  Connections marked in green are not blocked.  Those marked in red are blocked by the blacklist (on the next tab), those in orange and brown are blocked by filter files (see preferences to modify these).")
	}
	
	
	@IBAction func showBlockedTick(_ sender: NSButton!) {
		if (sender.state == .on) {
			show_blocked = 3
		} else {
			show_blocked = 0
		}
		UserDefaults.standard.set(show_blocked, forKey: "log_show_blocked")
		refresh(timer:nil)
	}
	
	
	@IBAction func searchFieldChanged(_ sender: NSSearchField) {
		//print("search: ",sender.stringValue)
		refresh(timer:nil)
	}
	
	@objc func updateTable (rowView: NSTableRowView, row:Int) -> Void {
		// update all of the buttons in table (called after
		// pressing a button changes blacklist state etc)
		let cell = rowView.view(atColumn:2) as! blButton
		cell.updateButton()
	}
	
	@objc func BlockBtnAction(sender : blButton!) {
		sender.clickButton()
		// update (without scrolling)...
		tableView.enumerateAvailableRowViews(updateTable)
		}
}

extension LogViewController: NSTableViewDataSource {
	func numberOfRows(in tableView: NSTableView) -> Int {
		return Int(get_filter_log_size());
	}
	
	func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
		guard let sortDescriptor = tableView.sortDescriptors.first else {
    return }
    asc = sortDescriptor.ascending
		UserDefaults.standard.set(asc, forKey: "log_asc")
		if (asc != oldDescriptors.first?.ascending) {
			refresh(timer:nil)
		}
	}
}

extension LogViewController: NSTableViewDelegate {
	
	func mapRow(row: Int) -> Int {
		//map from displayed row to row in log itself
		let log_last = Int(get_filter_log_size())-1
		if (row<0) { return 0 }
		if (row>log_last) { return log_last }
		if (asc) {
			return row
		} else {
			return log_last-row
		}
	}
	
	func invMapRow(r: Int) -> Int {
		//map from row in log to displayed row
		let log_last = Int(get_filter_log_size())-1
		if (r<0) { return 0 }
		if (r>log_last) { return log_last }
		if (asc) {
			return r
		} else {
			return log_last-r
		}
	}
	
	func getRowText(row: Int) -> String {
		let r = mapRow(row: row)
		let item_ptr = get_filter_log_row(Int32(r))
		var item = item_ptr!.pointee
		let time_str = String(cString: &item.time_str.0)
		let log_line = String(cString: &item.log_line.0)
		return time_str+" "+log_line
	}
	
	func setColor(cell: NSTableCellView, udp: Bool, white: Int, blocked: Int) {
		if (white==1) {
			cell.textField?.textColor = NSColor.systemGreen
			return
		}
		if ( !udp && (blocked==1) ) {// blocked from blocklist
			cell.textField?.textColor = NSColor.red
		} else if ( !udp && (blocked==2) ) { // blocked from hosts file list
			cell.textField?.textColor = NSColor.orange
		} else if ( !udp && (blocked==3) ) { // blocked from blocklists file list
			cell.textField?.textColor = NSColor.brown
		} else { // not blocked
			cell.textField?.textColor = NSColor.systemGreen
		}
	}
	
	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		var cellIdentifier: String = ""
		var content: String = ""
		var tip: String = ""
		
		// we display log in reverse order, i.e. youngest first
		//let log_last = Int(get_log_size())-1
		//if (row>log_last) { return nil	}
		let r = mapRow(row: row)
		let item_ptr = get_filter_log_row(Int32(r))
		var item = item_ptr!.pointee
		let time_str = String(cString: &item.time_str.0)
		let log_line = String(cString: &item.log_line.0)
		let blocked_log = Int(item.blocked)

		if tableColumn == tableView.tableColumns[0] {
			cellIdentifier = "TimeCell"
			content=time_str
		} else if tableColumn == tableView.tableColumns[1] {
			cellIdentifier = "ConnCell"
			content=log_line
			let buf = UnsafeMutablePointer<Int8>.allocate(capacity:Int(INET6_ADDRSTRLEN))
			get_filter_log_addr_name(Int32(r), buf, INET6_ADDRSTRLEN)
			let ip = String(cString: buf)
			var domain = String(cString: &item.bl_item.domain.0)
			if (domain.count == 0) {
				domain = ip
			}
			let name = String(cString: &item.bl_item.name.0)
			let port = String(Int(item.raw.dport))
			if (blocked_log == 0) {
				tip = "This connection to "+domain+" ("+ip+":"+port+") was not blocked."
			} else if (blocked_log == 1) {
				tip = "This connection to "+domain+" ("+ip+":"+port+") was blocked for application '"+name+"' by user black list."
			} else if (blocked_log == 2) {
				tip = "This connection to "+domain+" ("+ip+":"+port+") was blocked for all applications by hosts file."
			} else {
				tip = "This connection to "+domain+" ("+ip+":"+port+") was blocked for application '"+name+"' by hosts file."
			}			
		} else {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) as? blButton else {return nil}
			
			// maintain state for button
			let log_line = String(cString: &item.log_line.0)
			cell.udp = log_line.contains("QUIC")
			cell.bl_item = item.bl_item
			cell.updateButton()
			cell.action = #selector(BlockBtnAction)
			return cell
		}
		guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {return nil}
		cell.textField?.stringValue = content
		cell.textField?.toolTip = tip
		setColor(cell: cell, udp: false, white: 0, blocked: blocked_log)
		return cell
	}
	
	func copy(sender: AnyObject?){
		//print("copy Log")
		//var textToDisplayInPasteboard = ""
		let indexSet = tableView.selectedRowIndexes
		var text = ""
		for row in indexSet {
			text += getRowText(row: row)+"\n"
		}
		let pasteBoard = NSPasteboard.general
		pasteBoard.clearContents()
		pasteBoard.setString(text, forType:NSPasteboard.PasteboardType.string)
	}
	
	func selectall(sender: AnyObject?){
		tableView.selectAll(nil)
	}
	
}
