//
//  appViewController.swift
//  appFirewall
//
//  Created by Doug Leith on 12/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class appViewController: NSViewController {

func infoPopup(msg: String, sender: NSView) {
	let storyboard = NSStoryboard(name:"Main", bundle:nil)
	let controller : helpViewController = storyboard.instantiateController(withIdentifier: "HelpViewController") as! helpViewController
		
	let popover = NSPopover()
	popover.contentViewController = controller
	popover.contentSize = controller.view.frame.size
	popover.behavior = .transient; popover.animates = true
	popover.show(relativeTo: sender.bounds, of: sender, preferredEdge: NSRectEdge.minY)
	controller.message(msg:msg)
}
	
func selectall(sender: AnyObject?){}
@objc func copyLine(sender: AnyObject?){}
@objc func getInfo(sender: AnyObject?){}

}
