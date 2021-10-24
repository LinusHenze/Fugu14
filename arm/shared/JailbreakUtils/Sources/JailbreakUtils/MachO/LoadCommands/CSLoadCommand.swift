//
//  CSLoadCommand.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-14.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

public class CSLoadCommand: LoadCommand {
    public var type: LoadCommandType { .CodeSignature }
    public var cmdSize: UInt32 { 16 }
    
    public var csOffset: UInt32
    public var csSize: UInt32
    
    public required init(fromData data: Data) throws {
        guard let type = data.tryGetGeneric(type: UInt32.self) else {
            throw MachOError.ReadError
        }
        
        guard let size = data.tryGetGeneric(type: UInt32.self, offset: 4) else {
            throw MachOError.ReadError
        }
        
        guard LoadCommandType.fromRaw(type) == .CodeSignature && size == 16 else {
            throw MachOError.BadFormat
        }
        
        guard let csOffset = data.tryGetGeneric(type: UInt32.self, offset: 0x8) else {
            throw MachOError.ReadError
        }
        
        self.csOffset = csOffset
        
        guard let csSize = data.tryGetGeneric(type: UInt32.self, offset: 0xC) else {
            throw MachOError.ReadError
        }
        
        self.csSize = csSize
    }
}
