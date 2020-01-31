//
//  addRuleViewController.swift
//  appFirewall
//
//  Created by Doug Leith on 30/01/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

import Cocoa

class addRuleViewController: NSViewController {
  
	var app: String = ""
	var domain: String = ""

	@IBOutlet weak var appName: NSComboBox?
	@IBOutlet weak var domainName: NSComboBox?
		
	override func viewDidLoad() {
		super.viewDidLoad()
		let apps = getIntstalledApps()
		appName?.addItems(withObjectValues: apps)
	}

	@IBAction func appNameClick(_ sender: NSComboBox) {
		print(sender.stringValue)
		app = sender.stringValue
	}
	
	@IBAction func domainNameClick(_ sender: NSComboBox) {
		print(sender.stringValue)
		domain = sender.stringValue
		// allow pasting of values ?  search ?
	}
	
	@IBAction func okClick(_ sender: NSButton) {
		// add validity checks
		//add_blockitem2(app, domain)
		sender.window?.close()
	}
	
	@IBAction func cancelClick(_ sender: NSButton) {
		self.dismiss(self)
	}
	
}

