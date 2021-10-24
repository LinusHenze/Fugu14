//
//  SymTabLoadCommand.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-10.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

open class SymTabLoadCommand: LoadCommand {
    public var type: LoadCommandType { .SymTab }
    public var cmdSize: UInt32 { 0x18 }
    
    public var symOff: UInt32
    public var symCount: UInt32
    public var strOff: UInt32
    public var strSize: UInt32
    
    public required init(fromData data: Data) throws {
        guard let type = data.tryGetGeneric(type: UInt32.self) else {
            throw MachOError.ReadError
        }
        
        guard let size = data.tryGetGeneric(type: UInt32.self, offset: 4) else {
            throw MachOError.ReadError
        }
        
        guard LoadCommandType.fromRaw(type) == .SymTab && size == 0x18 else {
            throw MachOError.BadFormat
        }
        
        guard let off = data.tryGetGeneric(type: UInt32.self, offset: 0x8) else {
            throw MachOError.ReadError
        }
        
        symOff = off
        
        guard let count = data.tryGetGeneric(type: UInt32.self, offset: 0xC) else {
            throw MachOError.ReadError
        }
        
        symCount = count
        
        guard let sOff = data.tryGetGeneric(type: UInt32.self, offset: 0x10) else {
            throw MachOError.ReadError
        }
        
        strOff = sOff
        
        guard let sSize = data.tryGetGeneric(type: UInt32.self, offset: 0x14) else {
            throw MachOError.ReadError
        }
        
        strSize = sSize
    }
}
