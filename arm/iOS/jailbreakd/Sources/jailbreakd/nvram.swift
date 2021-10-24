//
//  nvram.swift
//  jailbreakd
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import IOKit_iOS

public enum UntetherState {
    case enabled
    case disabled
    case forceRestore
}

public func getUntetherState() -> UntetherState {
    var masterPort: io_master_t = 0
    let kr = IOMasterPort(bootstrap_port, &masterPort)
    guard kr == KERN_SUCCESS else {
        // Safety first
        return .disabled
    }
    
    let entry = IORegistryEntryFromPath(masterPort, "IODeviceTree:/options")
    guard entry != 0 else {
        // Safety first
        return .disabled
    }
    
    defer { IOObjectRelease(entry) }
    
    guard let nvramVar = IORegistryEntryCreateCFProperty(entry, "boot-args" as CFString, kCFAllocatorDefault, 0).takeRetainedValue() as? String else {
        // Safety first
        return .disabled
    }
    
    if nvramVar.contains("untether_force_restore") {
        return .forceRestore
    } else if nvramVar.contains("no_untether") {
        return .disabled
    }
    
    return .enabled
}
