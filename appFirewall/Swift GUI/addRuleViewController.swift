//
//  addRuleViewController.swift
//  appFirewall
//
//  Created by Doug Leith on 30/01/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

import Cocoa

class addRuleViewController: NSViewController {
  
	var mode: String = "" // blacklist or whitelist
	var parentController: appViewController? 
	var apps: [String] = getIntstalledApps() // list of available apps
	
	@IBOutlet weak var appName: NSSearchField?
	@IBOutlet weak var domainName: NSSearchField?

	override func viewDidLoad() {
		super.viewDidLoad()
		
		appName?.delegate = self
		if let cell = appName?.cell as? NSSearchFieldCell {
			// disable search icon
			cell.searchButtonCell = nil
		}
		
		domainName?.delegate = self
		if let cell = domainName?.cell as? NSSearchFieldCell {
			// disable search icon
			cell.searchButtonCell = nil
		}
		
		// add special entry to list of available apps
		apps.append("<all apps>")
	}
	
	@IBAction func appNameClick(_ sender: NSSearchField) {
		// invoke autocompletion in delegate (see below()
		sender.currentEditor()?.complete(sender)
	}
	
	@IBAction func domainNameClick(_ sender: NSSearchField) {
		// invoke autocompletion in delegate (see below()
		sender.currentEditor()?.complete(sender)
	}
	
	func isValidURL(str: String) -> Bool {
		let detector = try! NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
		if let match = detector.firstMatch(in: str, options: [], range: NSRange(location: 0, length: str.utf16.count)) {
				// it is a link, if the match covers the whole string
				return match.range.length == str.utf16.count
		} else {
				return false
		}
	}
	
	@IBAction func okClick(_ sender: NSButton) {
		guard let app = appName?.stringValue else { return }
		guard var domain = domainName?.stringValue else { return }
		// crude validity checks
		if (domain.count == 0) {
			// set default domain value
			domain = "<all connections>"
		}
		if ( (app.count == 0)
			|| ( (domain != "<all connections>") && !isValidURL(str:domain)) ) {
			// bad user input
			print("bad user input in addRule: ", app, " ", domain)
			sender.window?.close()
		}
		print("addRule adding with: mode=",mode,"app=",app,"domain=",domain)
		if mode == "blacklist" {
			add_blockitem2(app, domain)
		} else if mode == "whitelist" {
			add_whiteitem2(app, domain)
		}
		// update display and exit
		parentController?.refresh(timer:nil)
		sender.window?.close()
	}
	
	@IBAction func cancelClick(_ sender: NSButton) {
		self.dismiss(self)
	}
}

extension addRuleViewController: NSSearchFieldDelegate, NSTextViewDelegate {
	
	func control(_ control: NSControl, textView: NSTextView, completions words: [String],
  forPartialWordRange charRange: NSRange, indexOfSelectedItem index: UnsafeMutablePointer<Int>) -> [String] {
  	// autocomplete suggestions for domain search field
		index.pointee = -1 // don't force our suggestions upon user
		let text = textView.string
		var suggestions: [String] = []
		if let id = control.identifier?.rawValue {
			if id == "domainName" {
				let count =  search_log_domains(text)
				if (count == 0) { return [] }
				for i in 0...count-1 {
					suggestions.append(String(cString:get_suggestion(i)))
				}
			} else {// appName
				for app in apps {
					if ((app.lowercased()).contains(text.lowercased())) { suggestions.append(app) }
					if (suggestions.count == 10) { break }
				}
			}
		}
		//print(suggestions)
		return suggestions
	}

}
