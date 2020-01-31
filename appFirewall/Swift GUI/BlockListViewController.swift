//
//  BlockListViewController.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class BlockListViewController: appViewController {

	@IBOutlet weak var tableView: NSTableView?
	
	override func viewDidLoad() {
		super.viewDidLoad()
		appViewDidLoad(tableView: tableView, tab: 2, ascKey: "blocklist_asc", sortKeys:["app_name","domain"])
	}
	
	override func viewWillAppear() {
		super.viewWillAppear()
		appViewWillAppear()
	}
	
	@objc override func refresh(timer:Timer?) {
    var asc1: Int = 1
		if (!asc) { asc1 = -1 }
		if (sortKey == sortKeys[0]) {
			sort_block_list(Int32(asc1), 0)
		} else {
			sort_block_list(Int32(asc1), 1)
		}
		tableView?.reloadData() // refresh the table when it is redisplayed
		if (timer != nil) { timer?.invalidate() } // don't need regular refreshes
	}
	
	@IBAction func clickHelpButton(_ sender: helpButton?) {
		sender?.clickButton(msg:"Domains/apps added here will be blocked, unless overridden by the whitelist (overridden rules are highlighted in red).  You can use this to block domains for an app that are not blocked by the standard lists but which should be.  Applications can be dragged or pasted onto this window from Finder to block them.")
	}
	
	@IBAction func Click(_ sender: NSButton?) {
		// table button to remove from blocklist
		guard let row = sender?.tag else {print("WARNING: problem in blocklistView AllowBtnAction getting row");  return}
		let item = get_blocklist_item(Int32(row))
		del_blockitem(item)
		refresh(timer:nil) // update the GUI to show the change
	}
	
	override func getRowText(row: Int) -> String {
		let item = get_blocklist_item(Int32(row))
		let name = String(cString: get_blocklist_item_name(item))
		let addr_name = String(cString: get_blocklist_item_domain(item))
		return name+", "+addr_name
	}
	
	override func updateTable (rowView: NSTableRowView, row:Int) {}
	
	override func numTableRows()->Int {return Int(get_blocklist_size())}
	
	override 	func getTableCell(tableView: NSTableView, tableColumn: NSTableColumn?, row: Int) -> NSView? {
		// decide on table contents at specified col and row
		let item = get_blocklist_item(Int32(row))
		let name = String(cString: get_blocklist_item_name(item))
		let addr_name = String(cString: get_blocklist_item_addrname(item))
		let domain = String(cString: get_blocklist_item_domain(item))
		
		var cellIdentifier: String = ""
		var content: String = ""
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
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) as? blButton else {print("WARNING: problem in blocklistView making button cell");  return nil}
			cell.title = "Allow"
			cell.bl_item = item?.pointee
			cell.tag = row
			cell.action = #selector(self.Click)
			cell.toolTip = "Remove from black list"
			return cell
		}
		guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {print("WARNING: problem in blocklistView making non-button cell"); return nil}
		cell.textField?.stringValue = content
		cell.textField?.toolTip = name+": "+domain
		cell.textField?.textColor = NSColor.textColor
		if (is_white(item) == 1) {
			cell.textField?.textColor = NSColor.red
			cell.textField?.toolTip = name+": "+domain+". This connection for app "+name+" is whitelisted, which overrides blocking.  Remove from whitelist to block connection."
		}
		return cell
	}
	
	// display addRule sheet (allows user to manually add a new rule)
	@IBAction func openSheetClick(_ sender: NSButton) {
		let controller = self.storyboard!.instantiateController(withIdentifier: "addRuleViewController") as! addRuleViewController
		controller.mode = "blacklist"
		controller.parentController = self
		self.presentAsSheet(controller)
	}
	
	// allow users to block an app by dragging and dropping
	func add(apps:[NSPasteboardItem]?) {
		guard let items = apps else { return }
		for item in items {
			if let str = item.string(forType:.fileURL) {
				if let url = URL(string:str) { // string parses to a URL
					if let app = Bundle(url: url)?.executableURL?.lastPathComponent {
						// url points to a bundle with an executable, great !
						// we don't use this executable name though, but rather one
						// derived fromn url E.g. for Anaconda the executable is run.sh
						let appName = (url.deletingPathExtension()).lastPathComponent
						print("adding ",appName,"(",app,") to blocklist using drag and drop")
						add_blockitem2(appName, "<all connections>")
					}
				}
			}
		}
		refresh(timer:nil)
	}
	
	override func handleDrag(info: NSDraggingInfo, row: Int) {
		add(apps: info.draggingPasteboard.pasteboardItems)
	}
	
	// also allow to paste an app into table
	@objc override func pasteLine(sender: AnyObject?){
		add(apps: NSPasteboard.general.pasteboardItems)
	}
}
