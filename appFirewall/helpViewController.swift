//
//  helpViewController.swift
//  appFirewall
//
//  Created by Doug Leith on 16/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class helpViewController: NSViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do view setup here.
    }
    
	@IBOutlet weak var textbox: NSTextField!
	
	func message(msg: String) {
		textbox.stringValue = msg
	}

}
