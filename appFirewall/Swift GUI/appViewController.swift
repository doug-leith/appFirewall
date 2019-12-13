//
//  appViewController.swift
//  appFirewall
//
//  Created by Doug Leith on 12/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class appViewController: NSViewController {

var popover = NSPopover()
var popoverRow : Int = -1

func infoPopup(msg: String, sender: NSView, row: Int) {
	let storyboard = NSStoryboard(name:"Main", bundle:nil)
	let controller : helpViewController = storyboard.instantiateController(withIdentifier: "HelpViewController") as! helpViewController
	popover.contentViewController = controller
	popover.contentSize = controller.view.frame.size
	popover.behavior = .transient; popover.animates = false
	print("popover show")
	popover.delegate = self // so we can catch events
	popover.show(relativeTo: sender.bounds, of: sender, preferredEdge: NSRectEdge.minY)
	controller.message(msg:msg)
	popoverRow = row
}
	
func selectall(sender: AnyObject?){}
@objc func copyLine(sender: AnyObject?){}
@objc func getInfo(sender: AnyObject?){}
func disableTooltips(){}
func enableTooltips(){}
}

extension appViewController: NSPopoverDelegate {

func popoverWillShow(_ notification: Notification) {
	print("popover show")
	disableTooltips()
	}
	
func popoverWillClose(_ notification: Notification) {
	print("popover close")
	enableTooltips()
	}
	
}
