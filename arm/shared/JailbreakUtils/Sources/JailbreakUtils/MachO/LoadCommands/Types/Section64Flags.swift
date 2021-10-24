//
//  Section64Flags.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-10.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

public struct Section64Flags: OptionSet {
    public var rawValue: UInt32
    
    public var typeOnly: Section64Type {
        get {
            Section64Type.fromRaw(UInt8(self.rawValue & 0xFF))
        } set {
            let flags = self.flagsOnly.rawValue
            self.rawValue = flags | UInt32(newValue.rawValue)
        }
    }
    
    public var flagsOnly: Section64Flags {
        get {
            Section64Flags(rawValue: self.rawValue & ~0xFF)
        } set {
            let type = UInt32(self.typeOnly.rawValue)
            self.rawValue = (newValue.rawValue & ~0xFF) | type
        }
    }
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    public func Type(_ type: Section64Type) -> Section64Flags {
        return Section64Flags(rawValue: UInt32(type.rawValue))
    }
    
    static let AttrSomeInstructions  = Section64Flags(rawValue: 0x400)
    static let AttrPureInstructions  = Section64Flags(rawValue: 0x80000000)
}
