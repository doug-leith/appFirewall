//
//  LogViewController.swift
//  appFirewall
//


import Cocoa

class LogViewController: NSViewController {
	
	@IBOutlet weak var tableView: NSTableView!
	var timer : Timer!
	var asc: Bool = false // whether log is shown in ascending/descending order

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
		
		ConnsColumn.headerCell.title="Connections ("+String(Int(get_num_conns_blocked()))+" blocked)"
		
		refresh(timer: nil) // refresh the table when it is redisplayed
	}
	
	@objc func refresh(timer:Timer?) {
		var force : Bool = true
		if (timer != nil) {
			force = false
		}
		let firstVisibleRow = tableView.rows(in: tableView.visibleRect).location
		if (force
			  || (firstVisibleRow==0) // if scrolled down, don't update
						&& (has_log_changed() == 1)) {
			// log is updated by sniffing of new conns
			//print("log refresh")
			clear_log_changed()
			tableView.reloadData()
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
	
	@objc func BlockBtnAction(sender : NSButton!) {
		let row = sender.tag;
		var item = get_log_item(Int32(row))
		let name = String(cString: &item.bl_item.name.0)
		var bl_item = item.bl_item
		let domain = String(cString: &bl_item.domain.0)
		if ((name.count==0) || name.contains("<unknown>") ) {
			print("Tried to block item with process name <unknown> or ''")
			return // PID name is missing, we can't add this to block list
		}
		var white: Int = 0
		if (in_whitelist_htab(&bl_item, 0) != nil) {
			white = 1
		}
		var blocked: Int = 0
		if (in_blocklist_htab(&bl_item, 0) != nil) {
			blocked = 1
		} else if (in_hostlist_htab(domain) != nil) {
			blocked = 2
		} else if (in_blocklists_htab(&bl_item) != nil) {
			blocked = 3
		}
		
		if (sender.title.contains("Allow")) {
			if (blocked == 1) { // on block list, remove
				del_blockitem(&bl_item)
			} else if (blocked>1) { // on host list, add to whitelist
				add_whiteitem(&bl_item)
			}
		} else { // block
			if (white == 1) { // on white list, remove
				del_whiteitem(&bl_item)
			}
			if (blocked == 0) {
				add_blockitem(&bl_item)
			}
		}
		tableView.reloadData()
	}

}

extension LogViewController: NSTableViewDataSource {
	func numberOfRows(in tableView: NSTableView) -> Int {
		return Int(get_log_size());
	}
	
	func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
		guard let sortDescriptor = tableView.sortDescriptors.first else {
    return }
    asc = sortDescriptor.ascending
		UserDefaults.standard.set(asc, forKey: "log_asc")
		if (asc != oldDescriptors.first?.ascending) {
			tableView.reloadData()
		}
	}
}

extension LogViewController: NSTableViewDelegate {
	
	func mapRow(row: Int) -> Int {
		//map from displayed row to row in log itself
		let log_last = Int(get_log_size())-1
		if (row<0) { return 0 }
		if (row>log_last) { return log_last }
		if (asc) {
			return row
		} else {
			return log_last-row
		}
	}
	
	func getRowText(row: Int) -> String {
		let r = mapRow(row: row)
		/*let log_last = Int(get_log_size())-1
		if (row>log_last) { return ""	}
		let item = get_log_item(Int32(log_last-row))*/
		let item = get_log_item(Int32(r))
		let time_str = String(cString: item.time_str)
		let log_line = String(cString: item.log_line)
		return time_str+" "+log_line
	}
	
	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		var cellIdentifier: String = ""
		var content: String = ""
		var tip: String = ""
		
		// we display log in reverse order, i.e. youngest first
		//let log_last = Int(get_log_size())-1
		//if (row>log_last) { return nil	}
		let r = mapRow(row: row)
		var item = get_log_item(Int32(r))
		let time_str = String(cString: item.time_str)
		let log_line = String(cString: item.log_line)
		
		let blocked = Int(item.blocked)
		var white: Int = 0
		if (in_whitelist_htab(&item.bl_item, 0) != nil) {
			white = 1
		}
		var on_list: Int = 0
		if (in_blocklist_htab(&item.bl_item, 0) != nil) {
			on_list = 1
		}
		
		let udp : Bool = log_line.contains("QUIC")
		
		if tableColumn == tableView.tableColumns[0] {
			cellIdentifier = "TimeCell"
			content=time_str
		} else if tableColumn == tableView.tableColumns[1] {
			cellIdentifier = "ConnCell"
			content=log_line
			let buf = UnsafeMutablePointer<Int8>.allocate(capacity:Int(INET6_ADDRSTRLEN))
			get_log_addr_name(Int32(r), buf, INET6_ADDRSTRLEN)
			tip = String(cString: buf)
		} else {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSButton else {return nil}
			cell.tag = r
			if (udp) { // QUIC, can't block yet
				cell.title = ""
				cell.isEnabled = false
				return cell
			}
			if (blocked > 1) {
				if (white == 1) {
					cell.title = "Block"
					cell.toolTip = "Remove from white list"
				} else {
					cell.title = "Allow"
					cell.toolTip = "Add to white list"
				}
			} else if (on_list==1) {
				if (white==1) {
					cell.title = "Block"
					cell.toolTip = "Remove from white list"
				} else {
					cell.title = "Allow"
					cell.toolTip = "Remove from black list"
				}
			} else {
				if (white==1) {
					cell.title = "Remove"
					cell.toolTip = "Remove from white list"
				} else {
					cell.title = "Block"
					cell.toolTip = "Add to black list"
				}
			}
			cell.isEnabled = true
			cell.action = #selector(BlockBtnAction)
			return cell
		}
		guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {return nil}
		cell.textField?.stringValue = content
		cell.textField?.toolTip = tip
		if (blocked==1) {// blocked from blocklist
			cell.textField?.textColor = NSColor.red
		} else if (blocked==2) { // blocked from hosts list
			cell.textField?.textColor = NSColor.orange
		} else if ( (Int(item.raw.udp)==0) && (blocked==3) ) { // blocked from blocklists file list
			cell.textField?.textColor = NSColor.brown
		} else { // not blocked
			cell.textField?.textColor = NSColor.systemGreen
		}
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
