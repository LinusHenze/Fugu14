//
//  DSymTabLoadCommand.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-10.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

open class DSymTabLoadCommand: LoadCommand {
    public var type: LoadCommandType { .DSymTab }
    public var cmdSize: UInt32 { 0x50 }
    
    public var localSymOff: UInt32
    public var localSymCount: UInt32
    
    public var externalSymOff: UInt32
    public var externalSymCount: UInt32
    
    public var undefSymOff: UInt32
    public var undefSymCount: UInt32
    
    public var tocOff: UInt32
    public var tocCount: UInt32
    
    public var moduleTblOff: UInt32
    public var moduleTblCount: UInt32
    
    public var extSymTblOff: UInt32
    public var extSymTblCount: UInt32
    
    public var indirectOff: UInt32
    public var indirectCount: UInt32
    
    public var extRelOff: UInt32
    public var extRelCount: UInt32
    
    public var localRelOff: UInt32
    public var localRelCount: UInt32
    
    public required init(fromData data: Data) throws {
        guard let type = data.tryGetGeneric(type: UInt32.self) else {
            throw MachOError.ReadError
        }
        
        guard let size = data.tryGetGeneric(type: UInt32.self, offset: 4) else {
            throw MachOError.ReadError
        }
        
        guard LoadCommandType.fromRaw(type) == .DSymTab && size == 0x50 else {
            throw MachOError.BadFormat
        }
        
        guard let lsoff = data.tryGetGeneric(type: UInt32.self, offset: 0x8) else {
            throw MachOError.ReadError
        }
        
        localSymOff = lsoff
        
        guard let lscnt = data.tryGetGeneric(type: UInt32.self, offset: 0xC) else {
            throw MachOError.ReadError
        }
        
        localSymCount = lscnt
        
        guard let esoff = data.tryGetGeneric(type: UInt32.self, offset: 0x10) else {
            throw MachOError.ReadError
        }
        
        externalSymOff = esoff
        
        guard let escnt = data.tryGetGeneric(type: UInt32.self, offset: 0x14) else {
            throw MachOError.ReadError
        }
        
        externalSymCount = escnt
        
        guard let udoff = data.tryGetGeneric(type: UInt32.self, offset: 0x18) else {
            throw MachOError.ReadError
        }
        
        undefSymOff = udoff
        
        guard let udcnt = data.tryGetGeneric(type: UInt32.self, offset: 0x1C) else {
            throw MachOError.ReadError
        }
        
        undefSymCount = udcnt
        
        guard let tocoff = data.tryGetGeneric(type: UInt32.self, offset: 0x20) else {
            throw MachOError.ReadError
        }
        
        tocOff = tocoff
        
        guard let toccnt = data.tryGetGeneric(type: UInt32.self, offset: 0x24) else {
            throw MachOError.ReadError
        }
        
        tocCount = toccnt
        
        guard let modoff = data.tryGetGeneric(type: UInt32.self, offset: 0x28) else {
            throw MachOError.ReadError
        }
        
        moduleTblOff = modoff
        
        guard let modcnt = data.tryGetGeneric(type: UInt32.self, offset: 0x2C) else {
            throw MachOError.ReadError
        }
        
        moduleTblCount = modcnt
        
        guard let estoff = data.tryGetGeneric(type: UInt32.self, offset: 0x30) else {
            throw MachOError.ReadError
        }
        
        extSymTblOff = estoff
        
        guard let estcnt = data.tryGetGeneric(type: UInt32.self, offset: 0x34) else {
            throw MachOError.ReadError
        }
        
        extSymTblCount = estcnt
        
        guard let ioff = data.tryGetGeneric(type: UInt32.self, offset: 0x38) else {
            throw MachOError.ReadError
        }
        
        indirectOff = ioff
        
        guard let icount = data.tryGetGeneric(type: UInt32.self, offset: 0x3C) else {
            throw MachOError.ReadError
        }
        
        indirectCount = icount
        
        guard let eroff = data.tryGetGeneric(type: UInt32.self, offset: 0x40) else {
            throw MachOError.ReadError
        }
        
        extRelOff = eroff
        
        guard let ercount = data.tryGetGeneric(type: UInt32.self, offset: 0x44) else {
            throw MachOError.ReadError
        }
        
        extRelCount = ercount
        
        guard let lroff = data.tryGetGeneric(type: UInt32.self, offset: 0x48) else {
            throw MachOError.ReadError
        }
        
        localRelOff = lroff
        
        guard let lrcount = data.tryGetGeneric(type: UInt32.self, offset: 0x4C) else {
            throw MachOError.ReadError
        }
        
        localRelCount = lrcount
    }
}
