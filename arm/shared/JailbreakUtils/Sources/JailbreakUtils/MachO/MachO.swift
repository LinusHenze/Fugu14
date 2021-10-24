//
//  MachO.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-08.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

open class MachO {
    public var magic: MachOMagic
    public var cpuType: UInt32
    public var cpuSubType: UInt32
    public var filetype: MachOFiletype
    public var flags: MachOFlags
    
    public var cmds: [LoadCommand] = []
    
    public var uuid: uuid_t? {
        for cmd in cmds {
            if let uuidCmd = cmd as? UUIDLoadCommand {
                return uuidCmd.uuid
            }
        }
        
        return nil
    }
    
    public private(set) var data: Data
    
    private init(_ fromData: Data) throws {
        data = fromData
        
        // Read the MachO header
        guard let magic = data.tryGetGeneric(type: UInt32.self) else {
            throw MachOError.ReadError
        }
        
        self.magic = MachOMagic.fromRaw(magic)
        if case .Unknown = self.magic {
            if magic.bigEndian == 0xCAFEBABE {
                throw MachOError.FatNotMachO
            }
            
            throw MachOError.InvalidMagic
        }
        
        guard let cpuType = data.tryGetGeneric(type: UInt32.self, offset: 0x4) else {
            throw MachOError.ReadError
        }
        
        self.cpuType = cpuType
        
        guard let cpuSubType = data.tryGetGeneric(type: UInt32.self, offset: 0x8) else {
            throw MachOError.ReadError
        }
        
        self.cpuSubType = cpuSubType
        
        guard let filetype = data.tryGetGeneric(type: UInt32.self, offset: 0xC) else {
            throw MachOError.ReadError
        }
        
        self.filetype = MachOFiletype.fromRaw(filetype)
        
        guard let ncmds = data.tryGetGeneric(type: UInt32.self, offset: 0x10) else {
            throw MachOError.ReadError
        }
        
        guard let cmds_size = data.tryGetGeneric(type: UInt32.self, offset: 0x14) else {
            throw MachOError.ReadError
        }
        
        guard let flags = data.tryGetGeneric(type: UInt32.self, offset: 0x18) else {
            throw MachOError.ReadError
        }
        
        self.flags = MachOFlags(rawValue: flags)
        
        guard (cmds_size + 0x20) <= data.count else {
            throw MachOError.ReadError
        }
        
        var cmdsData = data.subdata(in: 0x20..<(0x20 + Int(cmds_size)))
        for _ in 0..<ncmds {
            let parsed = try OpaqueLoadCommand.parse(data: cmdsData)
            cmds.append(parsed)
            
            cmdsData = cmdsData.tryAdvance(by: Int(parsed.cmdSize))
        }
    }
    
    public convenience init(fromData: Data, okToLoadFAT: Bool = true) throws {
        do {
            try self.init(fromData)
        } catch MachOError.FatNotMachO {
            if !okToLoadFAT {
                throw MachOError.FatNotMachO
            }
            
            do {
                try self.init(FAT(fromData: fromData).bestArch().data)
            } catch MachOError.FatNotMachO {
                throw MachOError.NestedFAT
            }
        }
    }
    
    public convenience init(fromFile: String, okToLoadFAT: Bool = true) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: fromFile))
        try self.init(fromData: data, okToLoadFAT: okToLoadFAT)
    }
    
    public func findLoadCommand<Type: LoadCommand>(ofType: LoadCommandType) -> Type? {
        for c in cmds {
            if c.type == ofType {
                return c as? Type
            }
        }
        
        return nil
    }
    
    public func findSegmentLoadCommand(withName: String) -> Segment64LoadCommand? {
        for c in cmds {
            if let slc = c as? Segment64LoadCommand {
                if slc.name == withName {
                    return slc
                }
            }
        }
        
        return nil
    }
    
    public func getChainedFixups() throws -> ChainedFixups {
        return try ChainedFixups(machO: self)
    }
    
    public func getSymbolTable() throws -> SymbolTable {
        return try SymbolTable(machO: self)
    }
}
