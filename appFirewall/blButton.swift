//
//  blButton.swift
//  appFirewall
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
	var item_ptr: UnsafeMutablePointer<log_line_t>? = nil
}
