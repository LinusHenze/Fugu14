//
//  ChainedFixupsLoadCommand.swift
//  JailbreakUtils
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation

open class ChainedFixupsLoadCommand: LoadCommand {
    public var type: LoadCommandType { .ChainedFixups }
    public var cmdSize: UInt32 { 16 }
    
    public var fixupOffset: UInt32
    public var fixupSize: UInt32
    
    public required init(fromData data: Data) throws {
        guard let type = data.tryGetGeneric(type: UInt32.self) else {
            throw MachOError.ReadError
        }
        
        guard let size = data.tryGetGeneric(type: UInt32.self, offset: 4) else {
            throw MachOError.ReadError
        }
        
        guard LoadCommandType.fromRaw(type) == .ChainedFixups && size == 16 else {
            throw MachOError.BadFormat
        }
        
        guard let off = data.tryGetGeneric(type: UInt32.self, offset: 8) else {
            throw MachOError.ReadError
        }
        
        fixupOffset = off
        
        guard let fxSize = data.tryGetGeneric(type: UInt32.self, offset: 12) else {
            throw MachOError.ReadError
        }
        
        fixupSize = fxSize
    }
}
