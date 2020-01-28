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
	@IBOutlet weak var useMenuBar: NSButton!
	@IBOutlet weak var blockQUIC: NSButton!	
	@IBOutlet weak var useDOH: NSButton!
	
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
		useMenuBar.state = boolToState(value: Config.getUseMenuBar())
		blockQUIC.state = boolToState(value: Config.getBlockQUIC())
		useDOH.state = boolToState(value: Config.getDnscrypt_proxy())
	}
	
	@IBAction func autoCheckUpdatesClick(_ sender: NSButton!) {
		Config.autoCheckUpdates(value: stateToBool(state:autoCheckUpdates.state))
		Config.refresh()
	}
	
	@IBAction func autoUpdateClick(_ sender: Any) {
		Config.autoUpdate(value: stateToBool(state:autoUpdate.state))
	}
	
	@IBAction func runAtLoginClick(_ sender: Any) {
		Config.runAtLogin(value: stateToBool(state:runAtLogin.state))
		Config.refresh()
	}
	
	@IBAction func useMenuBarClick(_ sender: Any) {
		Config.useMenuBar(value: stateToBool(state:useMenuBar.state))
		Config.refresh()
	}
	
	
	@IBAction func blockQUICClick(_ sender: Any) {
		Config.blockQUIC(value: stateToBool(state:blockQUIC.state))
		Config.refresh()
	}
	
	
	@IBAction func blockQUICHelpClick(_ sender: helpButton?) {
		sender?.clickButton(msg:"This blocks traffic using Google's QUIC/UDP protocol, forcing Chrome etc to fallback to using TCP.  Unlike TCP traffic, just now appFirewall can't selectively block QUIC traffic.  Enabling this option is a workaround that allows Chrome traffic to be fully controlled. Its safe to enable, just not very elegant.")
	}
	
	@IBAction func DoHClick(_ sender: Any) {
		Config.dnscrypt_proxy(value: stateToBool(state:useDOH.state))
		Config.refresh()
	}
	
	
	@IBAction func DoHHelpClick(_ sender: helpButton?) {
		sender?.clickButton(msg:"This sets all network interfaces to use encrypted DNS-over-HTTPS.  It does this by redirecting DNS queries to 127.0.0.1 where they are resolved by an embedded copy of dnscrypt-proxy (see https://github.com/DNSCrypt/dnscrypt-proxy/wiki).")
	}
}
