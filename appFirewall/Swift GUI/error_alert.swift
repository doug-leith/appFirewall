//
//  error_alert.swift
//  appFirewall
//
//  Copyright © 2019 Doug Leith. All rights reserved.
//


import Foundation
import AppKit

func exit_popup(msg: String) {
	print(msg)
	let alert = NSAlert()
	alert.messageText = "Error"
	alert.informativeText = msg
	alert.alertStyle = .critical
	alert.addButton(withTitle: "OK")
	alert.runModal()
	exit(1)
}

