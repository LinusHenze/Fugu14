//
//  Segment64LoadCommand.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-10.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

open class Segment64LoadCommand: LoadCommand {
    public var type: LoadCommandType { .Segment64 }
    public var cmdSize: UInt32 { 72 + UInt32(sections.count) * 0x50 }
    
    private var _name: Data
    public  var name:  String { try! _name.toString(nullTerminated: true) }
    
    public var vmAddr: UInt64
    public var vmSize: UInt64
    
    public var fileOffset: UInt64
    public var fileSize:   UInt64
    
    public var maximumProt: VMProt
    public var protection:  VMProt
    
    public var flags: UInt32
    
    public class Section64 {
        private var _section: Data
        public var section: String { try! _section.toString(nullTerminated: true) }
        
        private var _segment: Data
        public var segment: String { try! _segment.toString(nullTerminated: true) }
        
        public var address: UInt64
        public var size:    UInt64
        
        public var offset:    UInt32
        public var alignment: UInt32
        
        public var relocOffset: UInt32
        public var relocCount:  UInt32
        
        public var flags: Section64Flags
        
        public var reserved1: UInt32
        public var reserved2: UInt32
        public var reserved3: UInt32
        
        public init(fromData data: Data) throws {
            guard let section = data.trySubdata(in: 0..<16) else {
                throw MachOError.ReadError
            }
            
            _ = try section.toString(nullTerminated: true)
            _section = section
            
            guard let segment = data.trySubdata(in: 0x10..<0x20) else {
                throw MachOError.ReadError
            }
            
            _ = try segment.toString(nullTerminated: true)
            _segment = segment
            
            guard let address = data.tryGetGeneric(type: UInt64.self, offset: 0x20) else {
                throw MachOError.ReadError
            }
            
            self.address = address
            
            guard let size = data.tryGetGeneric(type: UInt64.self, offset: 0x28) else {
                throw MachOError.ReadError
            }
            
            self.size = size
            
            guard let offset = data.tryGetGeneric(type: UInt32.self, offset: 0x30) else {
                throw MachOError.ReadError
            }
            
            self.offset = offset
            
            guard let alignment = data.tryGetGeneric(type: UInt32.self, offset: 0x34) else {
                throw MachOError.ReadError
            }
            
            self.alignment = alignment << 1
            
            guard let relocOffset = data.tryGetGeneric(type: UInt32.self, offset: 0x38) else {
                throw MachOError.ReadError
            }
            
            self.relocOffset = relocOffset
            
            guard let relocCount = data.tryGetGeneric(type: UInt32.self, offset: 0x3C) else {
                throw MachOError.ReadError
            }
            
            self.relocCount = relocCount
            
            guard let flags = data.tryGetGeneric(type: UInt32.self, offset: 0x40) else {
                throw MachOError.ReadError
            }
            
            self.flags = Section64Flags(rawValue: flags)
            
            guard let reserved1 = data.tryGetGeneric(type: UInt32.self, offset: 0x44) else {
                throw MachOError.ReadError
            }
            
            self.reserved1 = reserved1
            
            guard let reserved2 = data.tryGetGeneric(type: UInt32.self, offset: 0x48) else {
                throw MachOError.ReadError
            }
            
            self.reserved2 = reserved2
            
            guard let reserved3 = data.tryGetGeneric(type: UInt32.self, offset: 0x4C) else {
                throw MachOError.ReadError
            }
            
            self.reserved3 = reserved3
        }
    }
    
    public var sections: [Section64] = []
    
    public required init(fromData data: Data) throws {
        guard let type = data.tryGetGeneric(type: UInt32.self) else {
            throw MachOError.ReadError
        }
        
        guard let size = data.tryGetGeneric(type: UInt32.self, offset: 0x4) else {
            throw MachOError.ReadError
        }
        
        guard LoadCommandType.fromRaw(type) == .Segment64 && size >= 72 else {
            throw MachOError.BadFormat
        }
        
        guard let nSect = data.tryGetGeneric(type: UInt32.self, offset: 0x40) else {
            throw MachOError.ReadError
        }
        
        guard (size - 72) == nSect * 0x50 else {
            throw MachOError.BadFormat
        }
        
        guard let name = data.trySubdata(in: 8..<(8 + 16)) else {
            throw MachOError.ReadError
        }
        
        _ = try name.toString(nullTerminated: true)
        
        _name = name
        
        guard let vmAddr = data.tryGetGeneric(type: UInt64.self, offset: 0x18) else {
            throw MachOError.ReadError
        }
        
        self.vmAddr = vmAddr
        
        guard let vmSize = data.tryGetGeneric(type: UInt64.self, offset: 0x20) else {
            throw MachOError.ReadError
        }
        
        self.vmSize = vmSize
        
        guard let fileOffset = data.tryGetGeneric(type: UInt64.self, offset: 0x28) else {
            throw MachOError.ReadError
        }
        
        self.fileOffset = fileOffset
        
        guard let fileSize = data.tryGetGeneric(type: UInt64.self, offset: 0x30) else {
            throw MachOError.ReadError
        }
        
        self.fileSize = fileSize
        
        guard let maximumProt = data.tryGetGeneric(type: UInt32.self, offset: 0x38) else {
            throw MachOError.ReadError
        }
        
        self.maximumProt = VMProt(rawValue: maximumProt)
        
        guard let protection = data.tryGetGeneric(type: UInt32.self, offset: 0x3C) else {
            throw MachOError.ReadError
        }
        
        self.protection = VMProt(rawValue: protection)
        
        guard let flags = data.tryGetGeneric(type: UInt32.self, offset: 0x44) else {
            throw MachOError.ReadError
        }
        
        self.flags = flags
        
        var pos: Int = 0x48
        while pos < size {
            guard let tmp = data.trySubdata(in: pos..<(pos + 0x50)) else {
                throw MachOError.ReadError
            }
            
            sections.append(try Section64(fromData: tmp))
            pos += 0x50
        }
    }
}
