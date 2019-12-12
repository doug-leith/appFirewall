//
//  LogViewController.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class LogViewController: appViewController {
	
	@IBOutlet weak var tableView: NSTableView?
	var timer : Timer = Timer()
	@IBOutlet weak var searchField: NSSearchField?
	@IBOutlet weak var showBlockedButton: NSButton?
	var asc: Bool = false // whether log is shown in ascending/descending order
	var show_blocked: Int = 3

	@IBOutlet weak var tableHeader: NSTableHeaderView?

	@IBOutlet weak var ConnsColumn: NSTableColumn?
	
	override func viewDidLoad() {
		super.viewDidLoad()
		tableView!.delegate = self // force using ! since shouldn't fail
		tableView!.dataSource = self
		let menu = NSMenu()
		menu.addItem(NSMenuItem(title: "Copy", action: #selector(copyLine), keyEquivalent: ""))
		tableView?.menu = menu
	}
	
	override func viewWillAppear() {
		super.viewWillAppear()
		
		self.view.window?.setFrameUsingName("connsView") // restore to previous size
		UserDefaults.standard.set(1, forKey: "tab_index") // record active tab
		
		// enable click of column header to call sortDescriptorsDidChange action below
		asc = UserDefaults.standard.bool(forKey: "log_asc")
		if (tableView?.tableColumns[0].sortDescriptorPrototype==nil) {
			tableView?.tableColumns[0].sortDescriptorPrototype = NSSortDescriptor(key:"time",ascending:asc)
			tableView?.tableColumns[1].sortDescriptorPrototype = NSSortDescriptor(key:"conn",ascending:asc)
		}
	
		show_blocked = UserDefaults.standard.integer(forKey: "log_show_blocked")
		if (show_blocked == 0) {
			showBlockedButton?.state = .off
		} else {
			showBlockedButton?.state = .on
		}
		
		ConnsColumn?.headerCell.title="Connections ("+String(Int(get_num_conns_blocked()))+" blocked)"
		
		// schedule refresh of connections list every 1s
		timer = Timer.scheduledTimer(timeInterval: Config.viewRefreshTime, target: self, selector: #selector(refresh), userInfo: nil, repeats: true)
		timer.tolerance = 1 // we don't mind if it runs quite late
		refresh(timer: nil) // refresh the table when it is redisplayed
		
	}
	
	@objc func refresh(timer:Timer?) {
		// might happen if timer fires before/after view is loaded
		if (!isViewLoaded) { return }
		
 		var force : Bool = true
		if (timer != nil) {
			force = false
		}
		guard let rect = tableView?.visibleRect else {print("WARNING: problem in logView getting visible rect"); return}
		guard let firstVisibleRow = tableView?.rows(in: rect).location else {print("WARNING: problem in logView getting first visible row"); return}
		if (force || (has_log_changed() == 2) // force or log cleared
			  || ((firstVisibleRow==0) && (has_log_changed() != 0)) ) {
			clear_log_changed()
			filter_log_list(Int32(show_blocked),searchField?.stringValue)
			tableView?.reloadData()
		} else if (has_log_changed() == 1){
			// update scrollbars but leave rest of view alone.
			// shouldn't be used with view-based tables, see
			// https://developer.apple.com/documentation/appkit/nstableview/1534147-notenumberofrowschanged
			//tableView.noteNumberOfRowsChanged()
		}
		ConnsColumn?.headerCell.title="Connections ("+String(Int(get_num_conns_blocked()))+" blocked)"
	}

	override func viewWillDisappear() {
		//print("saving state")
		save_state()
		self.view.window?.saveFrame(usingName: "connsView") // record size of window
		timer.invalidate()
		super.viewWillDisappear()
	}
	
	
	@IBAction func helpButton(_ sender: helpButton?) {
			sender?.clickButton(msg:"This window logs the network connections made by the apps running on your computer.  Connections marked in green are not blocked.  Those marked in red are blocked by the blacklist (on the next tab), those in orange and brown are blocked by filter files (see preferences to modify these).  The numbers in brackets indicate multiple connections within a short time.  For some connections the app name may be marked as <not found>.  These are usually connections which are so brief (a millisecond or two) that we didn't manage to link the connection to an app before the app finished.  If you'd like to catch such connections try disabling SIP (System Integrity Protection) so that the firewall can use Dtrace - this requires a reboot but lets the firewall detect link connections to apps *much* more quickly.")
	}
	
	
	@IBAction func showBlockedTick(_ sender: NSButton?) {
		if (sender?.state == .on) {
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
		guard let cell = rowView.view(atColumn:2) as? blButton else {print("WARNING: problem in logView updateTable getting cell"); return}
		cell.updateButton()
	}
	
	@objc func BlockBtnAction(sender : blButton?) {
		sender?.clickButton()
		// update (without scrolling)...
		tableView?.enumerateAvailableRowViews(updateTable)
		}
		
	override func copyLine(sender: AnyObject?){
		guard let indexSet = tableView?.selectedRowIndexes else {print("WARNING: problem in logView copy getting index set"); return}
		var text = ""
		for row in indexSet {
			guard let cell0 = tableView?.view(atColumn:0, row:row,makeIfNecessary: true) as? NSTableCellView else {continue}
			guard let str0 = cell0.textField?.stringValue else {continue}
			guard let cell1 = tableView?.view(atColumn:1, row:row,makeIfNecessary: true) as? NSTableCellView else {continue}
			let str1 = cell1.textField?.stringValue ?? ""
			let tip = cell1.textField?.toolTip ?? ""
			text += str0+" "+str1+" ["+tip+"]\n"
		}
		let pasteBoard = NSPasteboard.general
		pasteBoard.clearContents()
		pasteBoard.setString(text, forType:NSPasteboard.PasteboardType.string)
	}
	
	override func selectall(sender: AnyObject?){
		tableView?.selectAll(nil)
	}
	
	override func getInfo(sender: AnyObject?){
		guard let row = tableView?.selectedRow else {print("WARNING: problem in logView getInfo getting selected row"); return}
		guard let cell = tableView?.view(atColumn:1, row:row,makeIfNecessary: true) as? NSTableCellView else {return}
		let str = cell.textField?.toolTip ?? ""
		infoPopup(msg: str, sender: cell)
	}
}

extension LogViewController: NSTableViewDataSource {
	func numberOfRows(in tableView: NSTableView) -> Int {
		return Int(get_filter_log_size());
	}
	
	func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
		guard let sortDescriptor = tableView.sortDescriptors.first else {
    print("WARNING: problem in logView getting sort descriptor"); return }
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
		
	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		var cellIdentifier: String = ""
		var content: String = ""
		var tip: String = ""
		
		// we display log in reverse order, i.e. youngest first
		let r = mapRow(row: row)
		if (r<0) { return nil }
		let item_ptr = get_filter_log_row(Int32(r))
		guard var item = item_ptr?.pointee else {print("WARNING: problem in logView getting item_ptr"); return nil}
		let time_str = String(cString: &item.time_str.0)
		let log_line = String(cString: &item.log_line.0)
		let blocked_log = Int(item.blocked)

		if tableColumn == tableView.tableColumns[0] {
			cellIdentifier = "TimeCell"
			content=time_str
		} else if tableColumn == tableView.tableColumns[1] {
			cellIdentifier = "ConnCell"
			content=log_line
			let ip = String(cString:get_filter_log_addr_name(Int32(r)))
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
			// add some info on whether IP is shared by multiple domains
			tip += " Domains associated with this IP address: "+String(cString:get_dns_count_str(item.raw.af, item.raw.dst_addr))
		} else {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) as? blButton else {print("WARNING: problem in logView making button cell"); return nil}
			
			// maintain state for button
			let log_line = String(cString: &item.log_line.0)
			cell.udp = log_line.contains("QUIC")
			cell.bl_item = item.bl_item
			cell.updateButton()
			cell.action = #selector(BlockBtnAction)
			return cell
		}
		guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {print("WARNING: problem in logView getting making non-button cell"); return nil}
		cell.textField?.stringValue = content
		cell.textField?.toolTip = tip
		setColor(cell: cell, udp: false, white: 0, blocked: blocked_log)
		return cell
	}
	

}
