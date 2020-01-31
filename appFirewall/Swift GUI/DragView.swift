//
//  DragView.swift
//  appFirewall
//
//  Created by Doug Leith on 30/01/2020.
//  Copyright © 2020 Doug Leith. All rights reserved.
//

import Cocoa

class DragView: NSView {

	required init?(coder aDecoder: NSCoder) {
			 super.init(coder: aDecoder)
			 registerForDraggedTypes([.URL])
			 print("drag init")
	}

	override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
		let pb = sender.draggingPasteboard
		print(pb.string(forType: .URL))
		print("performDragOperation")
		return true // accept
	}
		
	func draggingEntered(sender: NSDraggingInfo!) -> NSDragOperation  {
			print("draggingEntered")
		return NSDragOperation.copy
	}
	
}

