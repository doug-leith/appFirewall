//
//  ActiveConnsViewController.swift
//  appFirewall
//


import Cocoa

class ActiveConnsViewController: NSViewController {
	
	@IBOutlet weak var tableView: NSTableView!
	var timer : Timer!
	
	override func viewDidLoad() {
		// Do any additional setup after loading the view.
		super.viewDidLoad()
		tableView.delegate = self
		tableView.dataSource = self
		
		// schedule refresh of connections list every 1s
		timer = Timer.scheduledTimer(timeInterval: 1, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late
	}

	override func viewWillAppear() {
		// window is opening, populate it with content
		super.viewWillAppear()
		// manually set the initial size -- nothing else seemed to work !
		//preferredContentSize = NSSize(width: 850, height: 400)
		//self.view.window?.setFrame(NSRect(x:0,y:0,width: 850,height: 400), display: true)
		self.view.window?.setFrameUsingName("connsView") // restore to previous size
		UserDefaults.standard.set(0, forKey: "tab_index") // record active tab
		refresh()
	}
	
	@objc func refresh() {
		if (refresh_active_conns(0) == 1) { // set of conns has changed
			tableView.reloadData()
		}
	}

	override func viewWillDisappear() {
		// window is closing, save state
		super.viewWillDisappear()
		save_log()
		save_blocklist()
		save_dns_cache()
		self.view.window?.saveFrame(usingName: "connsView") // record size of window
	}
	
	@IBAction func Click(_ sender: NSButton!) {
		BlockBtnAction(sender: sender)
	}
	
	@objc func BlockBtnAction(sender : NSButton!) {
		let row = sender.tag
		let item = get_conns(Int32(row))
		if (on_blocklist(conn_to_bl_item(item)) >= 0) {
			// blocked connection, let's unblock it
			del_blockitem(conn_to_bl_item(item))
		} else {
			// open connection, let's block it
			add_blockitem(conn_to_bl_item(item))
		}
		tableView.reloadData()
	}
	
}

extension ActiveConnsViewController: NSTableViewDataSource {
	func numberOfRows(in tableView: NSTableView) -> Int {
		return Int(get_num_conns())
	}
}

extension ActiveConnsViewController: NSTableViewDelegate {
	
	func getRowText(row: Int) -> String {
		var item: conn_info_t = get_conns(Int32(row))
		let pid_name = String(cString: &item.pid_name.0)
		let conn_name = String(cString: &item.conn_name.0)
		return pid_name+" "+conn_name
	}
	
	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		var cellIdentifier: String = ""
		var content: String = ""
		
		var item: conn_info_t = get_conns(Int32(row))
		let pid_name = String(cString: &item.pid_name.0)
		let conn_name = String(cString: &item.conn_name.0)
		var bl_item = conn_to_bl_item(item)
		let domain = String(cString: &bl_item.domain.0)
		//print("active ", domain)
		
		var blocked: Int = 0
		if (on_blocklist(conn_to_bl_item(item)) >= 0) {
		//if (in_blocklist_htab(&bl_item) != nil) { // table lookup, faster !
			blocked = 1
		} else if (in_hostlist_htab(domain) != nil) {
			blocked = 2
		}
		
		let udp : Bool = conn_name.contains("QUIC")
		
		if tableColumn == tableView.tableColumns[0] {
			cellIdentifier = "ProcessCell"
			content=pid_name
		} else if tableColumn == tableView.tableColumns[1] {
			cellIdentifier = "ConnCell"
			content=conn_name
		} else if tableColumn == tableView.tableColumns[2] {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSButton else {return nil}
			cell.tag = row
			if (udp) {
				cell.title = ""
				cell.isEnabled = false
			} else {
				if (blocked==1) {
					cell.title = "Allow"
				} else {
					cell.title = "Block"
				}
				cell.isEnabled = true
				cell.action = #selector(BlockBtnAction)
			}
			return cell
		}
		guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {return nil}
		cell.textField?.stringValue = content
		if (blocked==1) {// blocked from blocklist
			cell.textField?.textColor = NSColor.red
		} else if (blocked==2) { // blocked from hosts list
			cell.textField?.textColor = NSColor.orange
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
}

