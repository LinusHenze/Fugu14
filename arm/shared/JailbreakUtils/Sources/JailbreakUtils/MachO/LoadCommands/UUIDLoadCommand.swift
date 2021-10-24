//
//  UUIDLoadCommand.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-09.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

open class UUIDLoadCommand: LoadCommand {
    public var type: LoadCommandType { .UUID }
    public var cmdSize: UInt32 { 24 }
    
    public var uuid: uuid_t
    
    public required init(fromData data: Data) throws {
        guard let type = data.tryGetGeneric(type: UInt32.self) else {
            throw MachOError.ReadError
        }
        
        guard let size = data.tryGetGeneric(type: UInt32.self, offset: 4) else {
            throw MachOError.ReadError
        }
        
        guard LoadCommandType.fromRaw(type) == .UUID && size == 24 else {
            throw MachOError.BadFormat
        }
        
        guard let uuid = data.tryGetGeneric(type: uuid_t.self, offset: 8) else {
            throw MachOError.ReadError
        }
        
        self.uuid = uuid
    }
}
