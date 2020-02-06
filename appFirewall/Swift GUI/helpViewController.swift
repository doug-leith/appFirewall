//
//  helpViewController.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class helpViewController: NSViewController {

	override func viewDidLoad() {
		super.viewDidLoad()
		message(msg: self.msg) // set text to be display and resize view to fit
	}
    
	@IBOutlet weak var textbox: NSTextField!
	var msg : String = ""
	
	func message(msg: String) {
		self.msg = msg
		// if view is loaded we refresh the text and resize the view to fit
		if (isViewLoaded) {
			textbox.stringValue = msg
			let fixedWidth = textbox.frame.size.width
			let newSize = textbox.sizeThatFits(CGSize(width: fixedWidth, height: 500))
			self.view.setFrameSize(newSize)
		}
	}
}
