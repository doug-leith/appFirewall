//
//  ConsentViewController.swift
//  appFirewall
//
//  Created by Doug Leith on 22/01/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

import Cocoa

class ConsentViewController: NSViewController {
	
	@IBOutlet var docView: NSTextView?
	
	override func viewDidLoad() {
		super.viewDidLoad()
    if let rtfPath = Bundle.main.url(forResource: "consent", withExtension: "rtf") {
			do {
				let attributedStringWithRtf: NSAttributedString = try NSAttributedString(url: rtfPath, options: [NSAttributedString.DocumentReadingOptionKey.documentType: NSAttributedString.DocumentType.rtf], documentAttributes: nil)
				docView?.textStorage?.setAttributedString(attributedStringWithRtf)
				docView?.textStorage?.foregroundColor = .textColor // set color so that adapt to light/dark mode
			 } catch let error {
					print("ERROR: Couldn't parse consent.rtf:", error )
			 }
		 } else {
		 	print("ERROR: Couldn't get consent.rtf from bundle!")
		}
	}
	
	@IBAction func clickAgree(_ sender: NSButton) {
		sender.window?.close()
		NSApp.stopModal()
	}
	
	@IBAction func clickCancel(_ sender: NSButton) {
		// exit app
		exit(0)
	}
}
