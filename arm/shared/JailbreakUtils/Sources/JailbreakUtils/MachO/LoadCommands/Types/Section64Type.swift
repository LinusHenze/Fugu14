//
//  Section64Type.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-10.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

public enum Section64Type: Equatable {
    private static let map = [
        .Regular:                         0x00,
        .ZeroFill:                        0x01,
        .CStringLiterals:                 0x02,
        .Literals4Byte:                   0x03,
        .Literals8Byte:                   0x04,
        .LiteralPointers:                 0x05,
        .NonLazySymbolPointers:           0x06,
        .LazySymbolPointers:              0x07,
        .SymbolStubs:                     0x08,
        .ModInitFuncPointers:             0x09,
        .ModTermFuncPointers:             0x0A,
        .Coalesced:                       0x0B,
        .GBZeroFill:                      0x0C,
        .Interposing:                     0x0D,
        .Literals16Byte:                  0x0E,
        .DtraceDOF:                       0x0F,
        .LazyDyLibSymbolPointers:         0x10,
        .ThreadLocalRegular:              0x11,
        .ThreadLocalZeroFill:             0x12,
        .ThreadLocalVariablePointers:     0x14,
        .ThreadLocalInitFunctionPointers: 0x15
    ] as KeyValuePairs<Section64Type, UInt8>
    
    public var rawValue: UInt8 {
        if let val = Section64Type.map[self] {
            return val
        }
        
        guard case .Unknown(let value) = self else {
            fatalError("\(self) not Unknown and not in Section64Type.map!")
        }
        
        return value
    }
    
    public static func fromRaw(_ rawValue: UInt8) -> Section64Type {
        if let key = Section64Type.map.firstKeyOf(value: rawValue) {
            return key
        }
        
        return Section64Type.Unknown(rawValue)
    }
    
    case Regular
    case ZeroFill
    case CStringLiterals
    case Literals4Byte
    case Literals8Byte
    case LiteralPointers
    case NonLazySymbolPointers
    case LazySymbolPointers
    case SymbolStubs
    case ModInitFuncPointers
    case ModTermFuncPointers
    case Coalesced
    case GBZeroFill
    case Interposing
    case Literals16Byte
    case DtraceDOF
    case LazyDyLibSymbolPointers
    case ThreadLocalRegular
    case ThreadLocalZeroFill
    case ThreadLocalVariables
    case ThreadLocalVariablePointers
    case ThreadLocalInitFunctionPointers
    
    case Unknown(UInt8)
}
