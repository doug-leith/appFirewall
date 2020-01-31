//
//  WhileListViewController.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class WhiteListViewController: appViewController {

	@IBOutlet weak var tableView: NSTableView?
	
	override func viewDidLoad() {
			super.viewDidLoad()
			appViewDidLoad(tableView: tableView,tab: 3, ascKey: "whitelist_asc", sortKeys:["app_name","domain"])
	}

	override func viewWillAppear() {
		super.viewWillAppear()
		appViewWillAppear()
	}
	
	@objc override func refresh(timer:Timer?) {
    var asc1: Int = 1
		if (!asc) { asc1 = -1 }
		if (sortKey == sortKeys[0]) {
			sort_white_list(Int32(asc1), 0)
		} else {
			sort_white_list(Int32(asc1), 1)
		}
		tableView?.reloadData() // refresh the table when it is redisplayed
		if (timer != nil) { timer?.invalidate() } // don't need regular refreshes
	}
	
	@IBAction func helpButton(_ sender: helpButton?) {
		sender?.clickButton(msg:"Domains/apps added here will never be blocked.  Use this list when, for example, a connection is mistakenly blocked.")
	}
	
	@IBAction func click(_ sender: NSButton?) {
		guard let row = sender?.tag else {print("WARNING: problem in whitelistView BlockBtnAction getting row"); return}
		let item = get_whitelist_item(Int32(row))
		del_whiteitem(item)
		refresh(timer:nil) // update the GUI to show the change
	}
	
	override 	func getRowText(row: Int) -> String {
		let item = get_whitelist_item(Int32(row))
		let name = String(cString: get_whitelist_item_name(item))
		let addr_name = String(cString: get_whitelist_item_domain(item))
		return name+", "+addr_name
	}
	
	override func updateTable (rowView: NSTableRowView, row:Int) {}

	override func numTableRows()->Int {return Int(get_whitelist_size())}

	override 	func getTableCell(tableView: NSTableView, tableColumn: NSTableColumn?, row: Int) -> NSView? {
		// decide on table contents at specified col and row
		let item = get_whitelist_item(Int32(row))
		let name = String(cString: get_whitelist_item_name(item))
		let domain = String(cString: get_whitelist_item_domain(item))
		
		var cellIdentifier: String = ""
		var content: String = ""
		if tableColumn == tableView.tableColumns[0] {
			cellIdentifier = "ProcessCell"
			content=name
		} else if tableColumn == tableView.tableColumns[1] {
			cellIdentifier = "ConnCell"
			content=domain
		} else if tableColumn == tableView.tableColumns[2] {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) as? blButton else {print("WARNING: problem in whitelistView making button cell"); return nil}
			cell.title = "Remove"
			cell.tag = row
			cell.bl_item = item?.pointee
			cell.action = #selector(self.click)
			cell.toolTip = "Remove from white list"
			return cell
		}
		guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {print("WARNING: problem in whitelistView making non-button cell"); return nil}
		cell.textField?.stringValue = content
		cell.textField?.toolTip = name+": "+domain
		cell.textField?.textColor = NSColor.textColor
		return cell
	}
	
	// display addRule sheet (allows user to manually add a new rule)
	@IBAction func openSheetClick(_ sender: NSButton) {
		let controller = self.storyboard!.instantiateController(withIdentifier: "addRuleViewController") as! addRuleViewController
		self.presentAsSheet(controller)
	}
	
	// allow users to whitelist an app by dragging and dropping
	override func handleDrag(info: NSDraggingInfo, row: Int) {
		guard let items = info.draggingPasteboard.pasteboardItems else {return}
		for item in items {
			if let str = item.string(forType:.fileURL) {
				if let url = URL(string:str) { // string parses to a URL
					if let app = Bundle(url: url)?.executableURL?.lastPathComponent {
						// url points to a bundle with an executable, great !
						print("adding ",app," to blocklist using drag and drop")
						add_whiteitem2(app, "<all connections>")
					}
				}
			}
		}
		refresh(timer:nil)
	}
}
