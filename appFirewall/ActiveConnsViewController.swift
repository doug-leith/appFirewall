//
//  ActiveConnsViewController.swift
//  appFirewall
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
		
		// schedule refresh of connections list every 1s
		timer = Timer.scheduledTimer(timeInterval: 2, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late
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
		refresh()
		//print(String(Double(DispatchTime.now().uptimeNanoseconds)/1.0e9),"finished activeConns viewWillAppear()")
	}
		
	override func viewDidAppear() {
		super.viewDidAppear()
	}
	
	@objc func refresh() {
		let firstVisibleRow = tableView.rows(in: tableView.visibleRect).location
		if ( (firstVisibleRow==0) // if scrolled down, don't update
			&& (refresh_active_conns(0) == 1) ) { // set of conns has changed
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
	}
	
	
	@IBAction func helpButton(_ sender: NSButton) {
				let storyboard = NSStoryboard(name:"Main", bundle:nil)
			let controller : helpViewController = storyboard.instantiateController(withIdentifier: "HelpViewController") as! helpViewController
			
			let popover = NSPopover()
			popover.contentViewController = controller
			popover.contentSize = controller.view.frame.size
			popover.behavior = .transient; popover.animates = true
			popover.show(relativeTo: sender.bounds, of: sender, preferredEdge: NSRectEdge.minY)
			controller.message(msg:String("This window logs the network connections currently being made by the apps running on your computer.  Note that since we can only block connections when then try to start its possible for some connections on the blacklist to be running temporarily, but they will be blocked when they try to restart."))
		}
	
	
	@IBAction func Click(_ sender: NSButton!) {
		BlockBtnAction(sender: sender)
	}
	
	@objc func BlockBtnAction(sender : NSButton!) {
		let r = sender.tag
		let item_ptr = get_conns(Int32(r))
		if (item_ptr == nil) { return }
		var bl_item = conn_to_bl_item(item_ptr)
		let domain = String(cString: &bl_item.domain.0)

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
	
	func getRowText(row: Int) -> String {
		let r = mapRow(row: row)
		let item_ptr = get_conns(Int32(r))
		if (item_ptr == nil) { return "" }
		var item = item_ptr!.pointee
		
		let pid_name = String(cString: &item.name.0)+" ("+String(Int(item.pid))+")"
		
		let domain = String(cString: &item.domain.0)
		var content: String=""
		if (domain.count>0) {
			content=domain+":"+String(Int(item.raw.dport))
		} else {
			content=String(cString: &item.dst_addr_name.0)+":"+String(Int(item.raw.dport))
		}
		return pid_name+" "+content
	}
	
	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		var cellIdentifier: String = ""
		var content: String = ""
		var tip: String = ""
	
		let r = mapRow(row: row)
		let item_ptr = get_conns(Int32(r))
		if (item_ptr == nil) { return nil }
		var item = item_ptr!.pointee
		var bl_item = conn_to_bl_item(item_ptr)
		let domain = String(cString: &bl_item.domain.0)

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
		
		//print(domain,white,blocked)
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
			if (blocked == 0) {
				tip = "Domain "+domain+" ("+ip+":"+port+") not blocked."
			} else if (blocked == 1) {
				tip = "Domain "+domain+" ("+ip+":"+port+") blocked for application '"+name+"' by user black list."
			} else if (blocked == 2) {
				tip = "Domain "+domain+" ("+ip+":"+port+") blocked for all applications by hosts file."
			} else {
				tip = "Domain "+domain+" ("+ip+":"+port+") blocked for application '"+name+"' by hosts file."
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
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSButton else {return nil}
			cell.tag = r
			if (Int(item.raw.udp)>0) {
				cell.title = ""
				cell.isEnabled = false
				return cell
			}
			if (blocked == 1) {
				if (white==1) {
					cell.title = "Block"
					cell.toolTip = "Remove from white list"
				} else {
					cell.title = "Allow"
					cell.toolTip = "Remove from black list"
				}
			} else if (blocked > 1) {
				if (white == 1) {
					cell.title = "Block"
					cell.toolTip = "Remove from white list"
				} else {
					cell.title = "Allow"
					cell.toolTip = "Add to white list"
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
		if (white==1) {
			cell.textField?.textColor = NSColor.systemGreen
			return cell
		}
		if ( (Int(item.raw.udp)==0) && (blocked==1) ) {// blocked from blocklist
			cell.textField?.textColor = NSColor.red
		} else if ( (Int(item.raw.udp)==0) && (blocked==2) ) { // blocked from hosts file list
			cell.textField?.textColor = NSColor.orange
		} else if ( (Int(item.raw.udp)==0) && (blocked==3) ) { // blocked from blocklists file list
			cell.textField?.textColor = NSColor.brown
		} else { // not blocked
			cell.textField?.textColor = NSColor.systemGreen
		}
		return cell		
	}
	
	func copy(sender: AnyObject?){
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

