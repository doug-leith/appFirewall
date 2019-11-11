//
//  BlockListViewController.swift
//  appFirewall
//


import Cocoa

class BlockListViewController: NSViewController {
	var timer : Timer!
	
	@IBOutlet weak var tableView: NSTableView!
	
	override func viewDidLoad() {
		super.viewDidLoad()
		tableView.delegate = self
		tableView.dataSource = self
	}
	
	override func viewWillAppear() {
		super.viewWillAppear()
		self.view.window?.setFrameUsingName("connsView") // restore to previous size
		UserDefaults.standard.set(1, forKey: "tab_index") // record active tab
		tableView.reloadData() // refresh the table when it is redisplayed
	}
	
	override func viewWillDisappear() {
		super.viewWillDisappear()
		//print("saving state")
		save_log()
		save_blocklist()
		save_dns_cache()
		self.view.window?.saveFrame(usingName: "connsView") // record size of window
	}
	
	@IBAction func Click(_ sender: NSButton!) {
		AllowBtnAction(sender: sender)
	}
	
	@objc func AllowBtnAction(sender : NSButton!) {
		let row = sender.tag;
		let item = get_blocklist_item(Int32(row))
		//let pid_name = String(cString: &item.name.0)
		//let conn_name = String(cString: &item.conn_name.0)
		//print("block click ", row, " ",pid_name," ",conn_name)
		del_blockitem(item)
		tableView.reloadData() // update the GUI to show the change
	}
}

extension BlockListViewController: NSTableViewDataSource {
	func numberOfRows(in tableView: NSTableView) -> Int {
		return Int(get_blocklist_size())
	}
}

extension BlockListViewController: NSTableViewDelegate {
	
	func getRowText(row: Int) -> String {
		var item = get_blocklist_item(Int32(row))
		let name = String(cString: &item.name.0)
		let addr_name = String(cString: &item.addr_name.0)
		return name+" "+addr_name
	}
	
	func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
		
		var cellIdentifier: String = ""
		var content: String = ""
		
		var item = get_blocklist_item(Int32(row))
		let name = String(cString: &item.name.0)
		let addr_name = String(cString: &item.addr_name.0)
		//print(row, pid_name, name, addr_name)
		
		if tableColumn == tableView.tableColumns[0] {
			cellIdentifier = "ProcessCell"
			content=name
		} else if tableColumn == tableView.tableColumns[1] {
			cellIdentifier = "ConnCell"
			content=addr_name
		} else if tableColumn == tableView.tableColumns[2] {
			cellIdentifier = "ButtonCell"
		}
		
		let cellId = NSUserInterfaceItemIdentifier(rawValue: cellIdentifier)
		if (cellIdentifier == "ButtonCell") {
			guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) as? NSButton else {return nil}
			cell.title = "Allow"
			cell.tag = row
			cell.action = #selector(self.AllowBtnAction)
			return cell
		}
		guard let cell = tableView.makeView(withIdentifier: cellId, owner: self) 	as? NSTableCellView else {return nil}
		cell.textField?.stringValue = content
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
