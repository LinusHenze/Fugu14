//
//  sb.swift
//  jailbreakd
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation

@_cdecl("update_springboard_plist")
func update_springboard_plist() {
    let springBoardPlist = NSMutableDictionary(contentsOfFile: "/var/mobile/Library/Preferences/com.apple.springboard.plist")!
    springBoardPlist["SBShowNonDefaultSystemApps"] = true
    springBoardPlist.write(toFile: "/var/mobile/Library/Preferences/com.apple.springboard.plist", atomically: true)
    
    try? FileManager.default.setAttributes([.posixPermissions: 0o755, .ownerAccountName: "mobile"], ofItemAtPath: "/var/mobile/Library/Preferences/com.apple.springboard.plist")
}
