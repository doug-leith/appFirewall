//
//  ActiveConnsViewController.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class ActiveConnsViewController: appViewController {
	
	@IBOutlet weak var tableView: NSTableView?
		
	override func viewDidLoad() {
		// Do any additional setup after loading the view.
		super.viewDidLoad()
		self.tab = 0
		self.ascKey = "active_asc"
		self.sortKeys = ["pid","domain"]
		
		tableView!.delegate = self // force using ! since shouldn't fail
		appViewDidLoad(tableView: tableView!)
		start_pid_watcher() // start pid monitoring thread, its ok to call this multiple times
	}

	override func viewWillAppear() {
		// window is opening, populate it with content
		super.viewWillAppear()
		appViewWillAppear()
	}
	
	@objc override func refresh(timer:Timer?) {
		// might happen if timer fires before/after view is closed
		if (!isViewLoaded) { return }
		
		var force : Bool = false;
		if (timer == nil) {
			force = true
		}
		guard let rect = tableView?.visibleRect else {print("WARNING: activeConns problem getting visible rectangle in refresh"); return}
		guard let firstVisibleRow = tableView?.rows(in: rect).location else {print("WARNING: activeConns problem getting first visible row in refresh"); return}
		//let changed = refresh_active_conns(0)
		if (force || ((firstVisibleRow==0) && (Int(get_pid_changed()) != 0)) ) {
			saveSelected() // save set of currently selected rows
			clear_pid_changed()
			update_gui_pid_list()
			tableView?.reloadData()
			restorePopover() //redraw getInfo popover if needed
		}
	}
	
	@IBAction func helpButton(_ sender: helpButton?) {
			sender?.clickButton(msg:"This window logs the network connections currently being made by the apps running on your computer.  Note that connections can sometimes take a few seconds to die, during which time they may remain visible here.")
		}
	
	@IBAction func Click(_ sender: blButton?) {
		BlockBtnAction(sender: sender)
	}
	
	override func numTableRows()->Int {return Int(get_num_gui_conns())}
}

extension ActiveConnsViewController: NSTableViewDelegate {

	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
			
		let r = mapRow(row: row)
		var item = get_gui_conn(Int32(r))
		var bl_item = conn_to_bl_item(&item)
		let blocked = Int(blocked_status(&bl_item))
		let white = Int(is_white(&bl_item))
		let hashStr = String(cString:conn_hash(&item));
		let ip = String(cString: &item.dst_addr_name.0)
		var domain = String(cString: &bl_item.domain.0)
		if (domain.count == 0) { domain = ip }
		
		var cellIdentifier: String = ""
		var content: String = ""
		var tip: String
		if tableColumn == tableView.tableColumns[0] {
			tip = "PID: "+String(Int(item.pid))
		} else {
			var blocked_log = blocked
			if (white==1) { blocked_log = 0; }
			tip = getTip(ip: ip, domain: domain, name: String(cString: &bl_item.name.0), port: String(Int(item.raw.dport)), blocked_log: blocked_log, domains: String(cString:get_dns_count_str(item.raw.af, item.raw.dst_addr)))
		}
		
		if tableColumn == tableView.tableColumns[0] {
			cellIdentifier = "ProcessCell"
			content=String(cString: &item.name.0)
		} else if tableColumn == tableView.tableColumns[1] {
			cellIdentifier = "ConnCell"
			content = domain
			if (Int(item.raw.udp)==1) {
				content = content + " (UDP/QUIC)"
			}
		} else if tableColumn == tableView.tableColumns[2] {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? blButton else {print("WARNING: problem in activeConns getting button cell"); return nil}
			cell.udp = (Int(item.raw.udp)>0)
			cell.bl_item = bl_item // take a copy so ok to free() later
			cell.tip = tip
			cell.hashStr = hashStr;
			// restore selected state of this row
			restoreSelected(row: row, hashStr: cell.hashStr)
			// set tool tip and title
			cell.updateButton()
			cell.action = #selector(BlockBtnAction)
			return cell
		} else {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {print("WARNING: problem in activeConns getting non-button cell"); return nil}
			cell.textField?.stringValue = content
			cell.textField?.toolTip = tip
			setColor(cell: cell, udp: (Int(item.raw.udp)==1), white: white, blocked: blocked)
			return cell
		}
	}
}

