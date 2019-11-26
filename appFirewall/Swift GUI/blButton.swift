//
//  blButton.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class blButton: NSButton {

	// we extend NSButton class to allow us to store a
	// pointer to the log entry that the row containing
	// the button refers to.  this is needed because the
	// log may be updated between the time the button is
	// created and when it is pressed. and so just using
	// the row of the log to identify the item may fail
	// (plus we can only store integers in button tag
	// property)
	//var item_ptr: UnsafeMutablePointer<bl_item_t>? = nil
	var bl_item: bl_item_t? = nil
	var udp : Bool = false
	
	func updateButton() {
		// refresh the contents based on current data
		var bl_item = self.bl_item!
		/*var white: Int = 0
		if (in_whitelist_htab(&bl_item, 0) != nil) {
			white = 1
		}
		var blocked: Int = 0
		let domain = String(cString: &bl_item.domain.0)
		if (in_blocklist_htab(&bl_item, 0) != nil) {
			blocked = 1
		} else if (in_hostlist_htab(domain) != nil) {
			blocked = 2
		} else if (in_blocklists_htab(&bl_item) != nil) {
			blocked = 3
		}*/
		let blocked = Int(blocked_status(&bl_item))
		let white = Int(is_white(&bl_item))
				
		if (self.udp) { // QUIC, can't block yet
			self.title = ""
			self.isEnabled = false
			return
		}
		if (blocked > 1) {
			if (white == 1) {
				self.title = "Block"
				self.toolTip = "Remove from white list"
			} else {
				self.title = "Allow"
				self.toolTip = "Add to white list"
			}
		} else if (blocked==1) {
			if (white==1) {
				self.title = "Block"
				self.toolTip = "Remove from white list"
			} else {
				self.title = "Allow"
				self.toolTip = "Remove from black list"
			}
		} else {
			if (white==1) {
				self.title = "Remove"
				self.toolTip = "Remove from white list"
			} else {
				self.title = "Block"
				self.toolTip = "Add to black list"
			}
		}
		self.isEnabled = true
	}
	
	func clickButton() {
		var bl_item = self.bl_item!
		
		let name = String(cString: &bl_item.name.0)
		if ((name.count==0) || name.contains("<unknown>") ) {
				print("Tried to block item with process name <unknown> or ''")
				return // PID name is missing, we can't add this to block list
		}
			
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
		
		if (self.title.contains("Allow")) {
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
	}
	
}
