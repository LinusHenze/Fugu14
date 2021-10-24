//
//  MachOMagic.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-08.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

public enum MachOMagic: Equatable {
    private static let map = [
        .Magic:   0xFEEDFACE,
        .Magic64: 0xFEEDFACF
    ] as KeyValuePairs<MachOMagic, UInt32>
    
    public var rawValue: UInt32 {
        if let val = MachOMagic.map[self] {
            return val
        }
        
        guard case .Unknown(let value) = self else {
            fatalError("\(self) not Unknown and not in MachOMagic.map!")
        }
        
        return value
    }
    
    public static func fromRaw(_ rawValue: UInt32) -> MachOMagic {
        if let key = MachOMagic.map.firstKeyOf(value: rawValue) {
            return key
        }
        
        return MachOMagic.Unknown(rawValue)
    }
    
    case Magic
    case Magic64
    
    case Unknown(UInt32)
}
