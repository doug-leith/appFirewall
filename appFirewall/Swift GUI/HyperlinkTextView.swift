//
//  HyperlinkTextView.swift
//  appFirewall
//
//  Created by Doug Leith on 29/11/2019.
//  Copyright © 2019 Doug Leith. All rights reserved.
//

import Cocoa
import AppKit

class HyperlinkTextView: NSTextView {
	override func mouseDown(with event: NSEvent) {
		super.mouseDown(with: event)
		openClickedHyperlink(with: event)
	}
	
	override func resetCursorRects() {
		super.resetCursorRects()
		addHyperlinkCursorRects()
	}
	
	/// Displays a hand cursor when a link is hovered over.
	private func addHyperlinkCursorRects() {
		guard let layoutManager = layoutManager, let textContainer = textContainer else {
			return
		}
		
		let attributedStringValue = attributedString()
		let range = NSRange(location: 0, length: attributedStringValue.length)
		
		attributedStringValue.enumerateAttribute(.link, in: range) { value, range, _ in
			guard value != nil else {
				return
			}
			
			let rect = layoutManager.boundingRect(forGlyphRange: range, in: textContainer)
			addCursorRect(rect, cursor: .pointingHand)
		}
	}
	
	/// Opens links when clicked.
	private func openClickedHyperlink(with event: NSEvent) {
		let attributedStringValue = attributedString()
		let point = convert(event.locationInWindow, from: nil)
		let characterIndex = characterIndexForInsertion(at: point)
		
		guard characterIndex < attributedStringValue.length else {
			return
		}
		
		let attributes = attributedStringValue.attributes(at: characterIndex, effectiveRange: nil)
		
		guard let urlString = attributes[.link] as? String, let url = URL(string: urlString) else {
			return
		}
		
		NSWorkspace.shared.open(url)
	}
}
