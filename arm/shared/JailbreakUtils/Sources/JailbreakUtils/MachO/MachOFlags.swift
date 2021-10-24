//
//  MachOFlags.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-08.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

public struct MachOFlags: OptionSet, CustomReflectable {
    public let rawValue: UInt32
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    public var customMirror: Mirror {
        return Mirror(self, children: allFlags())
    }
    
    public func allFlags() -> AnyCollection<Mirror.Child> {
        var flags = self.rawValue
        var flagsAr: [(String, Any)] = []
        if (self.rawValue & MachOFlags.NoUndefs.rawValue) != 0 {
            flags &= ~MachOFlags.NoUndefs.rawValue
            flagsAr.append(("NoUndefs", MachOFlags.NoUndefs.rawValue))
        }
        
        if (self.rawValue & MachOFlags.IncrLink.rawValue) != 0 {
            flags &= ~MachOFlags.IncrLink.rawValue
            flagsAr.append(("IncrLink", MachOFlags.IncrLink.rawValue))
        }
        
        if (self.rawValue & MachOFlags.DyldLink.rawValue) != 0 {
            flags &= ~MachOFlags.DyldLink.rawValue
            flagsAr.append(("DyldLink", MachOFlags.DyldLink.rawValue))
        }
        
        if (self.rawValue & MachOFlags.BindAtLoad.rawValue) != 0 {
            flags &= ~MachOFlags.BindAtLoad.rawValue
            flagsAr.append(("BindAtLoad", MachOFlags.BindAtLoad.rawValue))
        }
        
        if (self.rawValue & MachOFlags.Prebound.rawValue) != 0 {
            flags &= ~MachOFlags.Prebound.rawValue
            flagsAr.append(("Prebound", MachOFlags.Prebound.rawValue))
        }
        
        if (self.rawValue & MachOFlags.TwoLevel.rawValue) != 0 {
            flags &= ~MachOFlags.TwoLevel.rawValue
            flagsAr.append(("TwoLevel", MachOFlags.TwoLevel.rawValue))
        }
        
        if (self.rawValue & MachOFlags.PIE.rawValue) != 0 {
            flags &= ~MachOFlags.PIE.rawValue
            flagsAr.append(("PIE", MachOFlags.PIE.rawValue))
        }
        
        if flags != 0 {
            flagsAr.append(("Unknow", flags))
        }
        
        return AnyCollection<Mirror.Child>(flagsAr)
    }
    
    public static let NoUndefs   = MachOFlags(rawValue: 0x01)
    public static let IncrLink   = MachOFlags(rawValue: 0x02)
    public static let DyldLink   = MachOFlags(rawValue: 0x04)
    public static let BindAtLoad = MachOFlags(rawValue: 0x08)
    public static let Prebound   = MachOFlags(rawValue: 0x10)
    public static let TwoLevel   = MachOFlags(rawValue: 0x80)
    public static let PIE        = MachOFlags(rawValue: 0x200000)
}
