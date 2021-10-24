//
//  OpaqueLoadCommand.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-09.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

open class OpaqueLoadCommand: LoadCommand {
    public let type: LoadCommandType
    public var cmdSize: UInt32 { UInt32(data.count + 8) }
    public var data: Data
    
    public required init(fromData data: Data) throws {
        guard let type = data.tryGetGeneric(type: UInt32.self) else {
            throw MachOError.ReadError
        }
        
        self.type = LoadCommandType.fromRaw(type)
        
        guard var size = data.tryGetGeneric(type: UInt32.self, offset: 0x4) else {
            throw MachOError.ReadError
        }
        
        size -= 8 // Header
        
        guard (size + 8) <= data.count else {
            throw MachOError.ReadError
        }
        
        self.data = data.subdata(in: 8..<(8 + Int(size)))
    }
    
    public init(type: LoadCommandType, cmdData: Data) {
        self.type = type
        self.data = cmdData
    }
    
    public static func parse(data: Data) throws -> LoadCommand {
        guard let rawType = data.tryGetGeneric(type: UInt32.self) else {
            throw MachOError.ReadError
        }
        
        let type = LoadCommandType.fromRaw(rawType)
        switch type {
            case .Segment64:
                return try Segment64LoadCommand(fromData: data)
                
            case .UUID:
                return try UUIDLoadCommand(fromData: data)
                
            case .ChainedFixups:
                return try ChainedFixupsLoadCommand(fromData: data)
                
            case .SymTab:
                return try SymTabLoadCommand(fromData: data)
                
            case .DSymTab:
                return try DSymTabLoadCommand(fromData: data)
                
            case .CodeSignature:
                return try CSLoadCommand(fromData: data)
            
            default:
                return try OpaqueLoadCommand(fromData: data)
        }
    }
}
