//
//  appTabViewController.swift
//  
//
//  Created by Doug Leith on 10/12/2019.
//

import Cocoa

class appTabViewController: NSTabViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
				let tab_index = UserDefaults.standard.integer(forKey: "tab_index") // get tab
				self.tabView.selectTabViewItem(at:tab_index)
   }
    
}
