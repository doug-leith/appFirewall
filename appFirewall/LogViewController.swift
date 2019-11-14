//
//  LogViewController.swift
//  appFirewall
//


import Cocoa

class LogViewController: NSViewController {
	
	@IBOutlet weak var tableView: NSTableView!
	var timer : Timer!

	override func viewDidLoad() {
		super.viewDidLoad()
		tableView.delegate = self
		tableView.dataSource = self

		// schedule refresh of connections list every 1s
		timer = Timer.scheduledTimer(timeInterval: 1, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late
	}
	
	override func viewWillAppear() {
		super.viewWillAppear()
		self.view.window?.setFrameUsingName("connsView") // restore to previous size
		UserDefaults.standard.set(2, forKey: "tab_index") // record active tab
		refresh(timer: nil) // refresh the table when it is redisplayed
	}
	
	@objc func refresh(timer:Timer?) {
		var force : Bool = true
		if (timer != nil) {
			force = false
		}
		if (force || has_log_changed() == 1) { // log is updated by sniffing of new conns
			//print("log refresh")
			clear_log_changed()
			tableView.reloadData()
		}
	}

	override func viewWillDisappear() {
		super.viewWillDisappear()
		//print("saving state")
		save_log()
		save_blocklist()
		save_dns_cache()
		self.view.window?.saveFrame(usingName: "connsView") // record size of window
	}
	
	@objc func BlockBtnAction(sender : NSButton!) {
		let row = sender.tag;
		var item = get_log_item(Int32(row))
		let name = String(cString: &item.bl_item.name.0)
		if ((name.count==0) || name.contains("<unknown>") ) {
			print("Tried to block item with process name <unknown> or ''")
			return // PID name is missing, we can't add this to block list
		}
		//let addr_name = String(cString: &item.bl_item.addr_name.0)
		//print("name=",name, addr_name)
		var on_list: Int = 0
		//if (on_blocklist(item.bl_item) >= 0) {
		if (in_blocklist_htab(&item.bl_item, 0) != nil) {
			on_list = 1
		}
		if (on_list==1) {
			// on block list, let's remove it
			del_blockitem(item.bl_item)
		} else {
			// else let's add it to block list
			add_blockitem(item.bl_item)
		}
		tableView.reloadData()
	}

}

extension LogViewController: NSTableViewDataSource {
	func numberOfRows(in tableView: NSTableView) -> Int {
		return Int(get_log_size());
	}
}

extension LogViewController: NSTableViewDelegate {
	
	func getRowText(row: Int) -> String {
		let log_last = Int(get_log_size())-1
		if (row>log_last) { return ""	}
		let item = get_log_item(Int32(log_last-row))
		let time_str = String(cString: item.time_str)
		let log_line = String(cString: item.log_line)
		return time_str+" "+log_line
	}
	
	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		var cellIdentifier: String = ""
		var content: String = ""
		
		// we display log in reverse order, i.e. youngest first
		let log_last = Int(get_log_size())-1
		if (row>log_last) { return nil	}
		var item = get_log_item(Int32(log_last-row))
		let time_str = String(cString: item.time_str)
		let log_line = String(cString: item.log_line)
		
		let blocked = Int(item.blocked)
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
		} else {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSButton else {return nil}
			cell.tag = log_last-row
			if (udp) {
				cell.title = ""
				cell.isEnabled = false
			} else {
				if (on_list==1) {
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
