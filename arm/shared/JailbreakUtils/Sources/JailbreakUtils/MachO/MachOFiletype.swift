//
//  MachOFiletype.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-08.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

public enum MachOFiletype: Equatable {
    private static let map = [
        .Object:   0x1,
        .Execute:  0x2,
        .FVMLib:   0x3,
        .Core:     0x4,
        .Preload:  0x5,
        .DyLib:    0x6,
        .DyLinker: 0x7,
        .Bundle:   0x8
    ] as KeyValuePairs<MachOFiletype, UInt32>
    
    public var rawValue: UInt32 {
        if let val = MachOFiletype.map[self] {
            return val
        }
        
        guard case .Unknown(let value) = self else {
            fatalError("\(self) not Unknown and not in MachOFiletype.map!")
        }
        
        return value
    }
    
    public static func fromRaw(_ rawValue: UInt32) -> MachOFiletype {
        if let key = MachOFiletype.map.firstKeyOf(value: rawValue) {
            return key
        }
        
        return MachOFiletype.Unknown(rawValue)
    }
    
    case Object
    case Execute
    case FVMLib
    case Core
    case Preload
    case DyLib
    case DyLinker
    case Bundle
    
    case Unknown(UInt32)
}
