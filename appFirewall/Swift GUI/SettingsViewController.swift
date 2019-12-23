//
//  SettingsViewController.swift
//  appFirewall
//
//  Created by Doug Leith on 22/12/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa

class SettingsViewController: NSViewController {

	@IBOutlet weak var autoCheckUpdates: NSButton!
	@IBOutlet weak var autoUpdate: NSButton!
	@IBOutlet weak var runAtLogin: NSButton!

	func boolToState(value: Bool) -> NSControl.StateValue {
		if (value) {
			return .on
		} else {
			return .off
		}
	}
	
	func stateToBool(state: NSControl.StateValue) -> Bool {
		if (state == .on) {
			return true
		} else {
			return false
		}
	}

	override func viewDidLoad() {
		super.viewDidLoad()
		autoCheckUpdates.state = boolToState(value: Config.getAutoCheckUpdates())
		autoUpdate.state = boolToState(value: Config.getAutoUpdate())
		runAtLogin.state = boolToState(value: Config.getRunAtLogin())
		//runAtLogin.isEnabled = false // for now
	}
	
	@IBAction func autoCheckUpdatesClick(_ sender: Any) {
		autoCheckUpdates.setNextState() // toggle
		Config.autoCheckUpdates(value: stateToBool(state:autoCheckUpdates.state))
		Config.refresh()
	}
	
	@IBAction func autoUpdateClick(_ sender: Any) {
		autoUpdate.setNextState() // toggle
		Config.autoUpdate(value: stateToBool(state:autoUpdate.state))
	}
	
	@IBAction func runAtLoginClick(_ sender: Any) {
		runAtLogin.setNextState() // toggle
		Config.runAtLogin(value: stateToBool(state:runAtLogin.state))
		Config.refresh()
	}
	
}
