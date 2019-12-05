//
//  BlockListViewController.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class BlockListViewController: NSViewController {

	var asc: Bool = true
	@IBOutlet weak var tableView: NSTableView?
	
	override func viewDidLoad() {
		super.viewDidLoad()
		tableView!.delegate = self
		tableView!.dataSource = self
	}
	
	override func viewWillAppear() {
		super.viewWillAppear()
		self.view.window?.setFrameUsingName("connsView") // restore to previous size
		UserDefaults.standard.set(2, forKey: "tab_index") // record active tab

		// enable click of column header to call sortDescriptorsDidChange action below
		asc = UserDefaults.standard.bool(forKey: "blocklist_asc")
		if (tableView?.tableColumns[0].sortDescriptorPrototype==nil) {
			tableView?.tableColumns[0].sortDescriptorPrototype = NSSortDescriptor(key:"app_name",ascending:asc)
			tableView?.tableColumns[1].sortDescriptorPrototype = NSSortDescriptor(key:"domain",ascending:asc)
		}
		tableView?.reloadData() // refresh the table when it is redisplayed
	}
	
	override func viewWillDisappear() {
		super.viewWillDisappear()
		save_state()
		self.view.window?.saveFrame(usingName: "connsView") // record size of window
	}
	

	@IBAction func clickHelpButton(_ sender: helpButton?) {
		sender?.clickButton(msg:"Domains/apps added here will always be blocked.  For example, you can use this to block domains for an app that are not blocked by the standard lists but which should be.")
	}
	
	@IBAction func Click(_ sender: NSButton?) {
		// table button to remove from blocklist
		AllowBtnAction(sender: sender)
	}
	
	@objc func AllowBtnAction(sender : NSButton?) {
		guard let row = sender?.tag else {print("WARNING: problem in blocklistView AllowBtnAction getting row");  return}
		let item = get_blocklist_item(Int32(row))
		del_blockitem(item)
		tableView?.reloadData() // update the GUI to show the change
	}
}

extension BlockListViewController: NSTableViewDataSource {
	func numberOfRows(in tableView: NSTableView) -> Int {
		return Int(get_blocklist_size())
	}
	
	func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
		var asc1: Int = 1
		guard let sortDescriptor = tableView.sortDescriptors.first else {
    print("WARNING: problem in blocklistView getting sort descriptor");  return }
    asc = sortDescriptor.ascending
		UserDefaults.standard.set(asc, forKey: "blocklist_asc")
		if (!asc) {
			asc1 = -1
		}
		if (sortDescriptor.key == "app_name") {
			sort_block_list(Int32(asc1), 0)
		} else {
			sort_block_list(Int32(asc1), 1)
		}
		tableView.reloadData()
	}
}

extension BlockListViewController: NSTableViewDelegate {
	
	func getRowText(row: Int) -> String {
		let item = get_blocklist_item(Int32(row))
		let name = String(cString: get_blocklist_item_name(item))
		let addr_name = String(cString: get_blocklist_item_domain(item))
		return name+", "+addr_name
	}
	
	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		var cellIdentifier: String = ""
		var content: String = ""
		
		let item = get_blocklist_item(Int32(row))
		let name = String(cString: get_blocklist_item_name(item))
		let addr_name = String(cString: get_blocklist_item_addrname(item))
		let domain = String(cString: get_blocklist_item_domain(item))
		
		if tableColumn == tableView.tableColumns[0] {
			cellIdentifier = "ProcessCell"
			content=name
		} else if tableColumn == tableView.tableColumns[1] {
			cellIdentifier = "ConnCell"
			if (domain.count>0) {
				content=domain
			} else {
				content=addr_name
			}
		} else if tableColumn == tableView.tableColumns[2] {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) as? NSButton else {print("WARNING: problem in blocklistView making button cell");  return nil}
			cell.title = "Allow"
			cell.tag = row
			cell.action = #selector(self.AllowBtnAction)
			cell.toolTip = "Remove from black list"
			return cell
		}
		guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {print("WARNING: problem in blocklistView making non-button cell"); return nil}
		cell.textField?.stringValue = content
		return cell
	}
	
	func copy(sender: AnyObject?){
		guard let indexSet = tableView?.selectedRowIndexes else {print("WARNING: problem in blocklistView copy getting index set"); return}
		var text = ""
		for row in indexSet {
			text += getRowText(row: row)+"\n"
		}
		let pasteBoard = NSPasteboard.general
		pasteBoard.clearContents()
		pasteBoard.setString(text, forType:NSPasteboard.PasteboardType.string)
	}
	
	func selectall(sender: AnyObject?){
		tableView?.selectAll(nil)
	}
}
