//
//  SymbolTable.swift
//  JailbreakUtils
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation

public enum SymbolTableError: Error {
    case noSymbols
}

open class SymbolTable {
    public var symbols: [Symbol] = []
    public var dSymbols: [Symbol] = []
    
    public init(machO: MachO) throws {
        guard let symTabInfo: SymTabLoadCommand = machO.findLoadCommand(ofType: .SymTab) else {
            throw SymbolTableError.noSymbols
        }
        
        guard (symTabInfo.symOff + 16 * symTabInfo.symCount) < machO.data.count else {
            throw MachOError.BadFormat
        }
        
        guard (symTabInfo.strOff + symTabInfo.strSize) < machO.data.count else {
            throw MachOError.BadFormat
        }
        
        let strTab = machO.data.subdata(in: Int(symTabInfo.strOff)..<Int(symTabInfo.strOff + symTabInfo.strSize))
        
        var cur = machO.data.advanced(by: Int(symTabInfo.symOff))
        for _ in 0..<symTabInfo.symCount {
            symbols.append(try Symbol(withData: cur, strTab: strTab))
            
            cur = cur.tryAdvance(by: 16)
        }
        
        if let dsymInfo: DSymTabLoadCommand = machO.findLoadCommand(ofType: .DSymTab) {
            guard (dsymInfo.indirectOff + 4 * dsymInfo.indirectCount) < machO.data.count else {
                throw MachOError.BadFormat
            }
            
            var cur = machO.data.advanced(by: Int(dsymInfo.indirectOff))
            for _ in 0..<dsymInfo.indirectCount {
                let entry = Int(cur.getGeneric(type: UInt32.self))
                guard entry < symbols.count else {
                    throw MachOError.BadFormat
                }
                
                dSymbols.append(symbols[entry])
                
                cur = cur.tryAdvance(by: 4)
            }
        }
    }
    
    public func symbol(forAddress: UInt64) -> Symbol? {
        for s in symbols {
            if s.value == forAddress {
                return s
            }
        }
        
        return nil
    }
    
    public struct Symbol {
        public var name: String
        public var type: UInt8
        public var section: UInt8
        public var desc: UInt16
        public var value: UInt64
        
        public init(withData data: Data, strTab: Data) throws {
            guard let strOff = data.tryGetGeneric(type: UInt32.self) else {
                throw MachOError.ReadError
            }
            
            guard strOff < strTab.count else {
                throw MachOError.BadFormat
            }
            
            name = try strTab.advanced(by: Int(strOff)).toString(encoding: .utf8, nullTerminated: true)
            
            guard let type = data.tryGetGeneric(type: UInt8.self, offset: 0x4) else {
                throw MachOError.ReadError
            }
            
            self.type = type
            
            guard let section = data.tryGetGeneric(type: UInt8.self, offset: 0x5) else {
                throw MachOError.ReadError
            }
            
            self.section = section
            
            guard let desc = data.tryGetGeneric(type: UInt16.self, offset: 0x6) else {
                throw MachOError.ReadError
            }
            
            self.desc = desc
            
            guard let value = data.tryGetGeneric(type: UInt64.self, offset: 0x8) else {
                throw MachOError.ReadError
            }
            
            self.value = value
        }
    }
}
