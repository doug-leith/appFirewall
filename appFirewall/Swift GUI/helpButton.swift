//
//  helpButton.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class helpButton: NSButton {
	func clickButton(msg:String) {
		let storyboard = NSStoryboard(name:"Main", bundle:nil)
		let controller : helpViewController = storyboard.instantiateController(withIdentifier: "HelpViewController") as! helpViewController
			
		let popover = NSPopover()
		popover.contentViewController = controller
		popover.contentSize = controller.view.frame.size
		popover.behavior = .transient; popover.animates = true
		popover.show(relativeTo: self.bounds, of: self, preferredEdge: NSRectEdge.minY)
		controller.message(msg:msg)
	}
}
