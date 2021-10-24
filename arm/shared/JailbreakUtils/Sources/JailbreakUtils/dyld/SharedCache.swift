//
//  SharedCache.swift
//  JailbreakUtils
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation

public enum SharedCacheError: Error {
    case dyldFuncNotFound
    case noSharedCache
    case imageNotFound(path: String)
    case noImageArray
    case classNotFound(class: String)
    case selectorNotFound(selector: String)
    case pointerNotInSharedCachePleaseDetachDebuggerAndTryAgain
}

open class SharedCache {
    public let cachePtr: UnsafeRawPointer
    public let cacheSize: Int
    
    public static var running = {
        return try! SharedCache()
    }()
    
    public var mappings: [SharedCacheMapping] {
        getMappings()
    }
    
    public var slide: UInt64 {
        UInt64(UInt(bitPattern: cachePtr)) - images[0].address
    }
    
    public var images: [SharedCacheImage] {
        getImages()
    }
    
    public var uuid: uuid_t {
        cachePtr.advanced(by: 88).assumingMemoryBound(to: uuid_t.self).pointee
    }
    
    public var acceleratorInfo: AcceleratorInfo {
        let start = cachePtr.advanced(by: 120).assumingMemoryBound(to: UInt64.self).pointee
        return AcceleratorInfo(withPtr: UnsafeRawPointer(bitPattern: Int(start + slide))!)
    }
    
    public init() throws {
        guard let funcPtr = dlsym(dlopen(nil, 0), "_dyld_get_shared_cache_range") else {
            throw SharedCacheError.dyldFuncNotFound
        }
        
        typealias shCacheFuncType = @convention(c) (_: UnsafeMutablePointer<Int>) -> UnsafeRawPointer?
        let shCacheFunc = unsafeBitCast(funcPtr, to: shCacheFuncType.self)
        var shCacheSize = 0
        
        guard let shCache = shCacheFunc(&shCacheSize) else {
            throw SharedCacheError.noSharedCache
        }
        
        cachePtr = shCache
        cacheSize = shCacheSize
    }
    
    public func getMappings() -> [SharedCacheMapping] {
        let offset = cachePtr.advanced(by: 16).assumingMemoryBound(to: UInt32.self).pointee
        let count = cachePtr.advanced(by: 20).assumingMemoryBound(to: UInt32.self).pointee
        
        var res: [SharedCacheMapping] = []
        
        var current = cachePtr.advanced(by: Int(offset))
        for _ in 0..<count {
            res.append(SharedCacheMapping(withPtr: current))
            
            current = current.advanced(by: SharedCacheMapping.structSize)
        }
        
        return res
    }
    
    public func getImages() -> [SharedCacheImage] {
        let offset = cachePtr.advanced(by: 24).assumingMemoryBound(to: UInt32.self).pointee
        let count = cachePtr.advanced(by: 28).assumingMemoryBound(to: UInt32.self).pointee
        
        var res: [SharedCacheImage] = []
        
        var current = cachePtr.advanced(by: Int(offset))
        for _ in 0..<count {
            res.append(SharedCacheImage(withPtr: current, base: cachePtr))
            
            current = current.advanced(by: SharedCacheImage.structSize)
        }
        
        return res
    }
    
    public func imageNumber(for path: String) throws -> UInt32 {
        let images = self.images
        
        for i in 0..<images.count {
            if images[i].path == path {
                return UInt32(i) + 1
            }
        }
        
        throw SharedCacheError.imageNotFound(path: path)
    }
    
    public struct SharedCacheMapping {
        static var structSize: Int = 32
        
        public var address: UInt64 = 0
        public var size: UInt64 = 0
        public var fileOffset: UInt64 = 0
        public var maximumProtection: UInt32 = 0
        public var initialProtection: UInt32 = 0
        
        public init() {}
        
        public init(withPtr: UnsafeRawPointer) {
            address = withPtr.assumingMemoryBound(to: UInt64.self).pointee
            size = withPtr.advanced(by: 8).assumingMemoryBound(to: UInt64.self).pointee
            fileOffset = withPtr.advanced(by: 16).assumingMemoryBound(to: UInt64.self).pointee
            maximumProtection = withPtr.advanced(by: 24).assumingMemoryBound(to: UInt32.self).pointee
            initialProtection = withPtr.advanced(by: 28).assumingMemoryBound(to: UInt32.self).pointee
        }
    }
    
    public struct SharedCacheImage {
        static var structSize: Int = 32
        
        public var address: UInt64 = 0
        public var modTime: UInt64 = 0
        public var inode: UInt64 = 0
        public var pathFileOffset: UInt32 = 0
        public var pad: UInt32 = 0
        
        public var path: String = ""
        
        public init() {}
        
        public init(withPtr: UnsafeRawPointer, base: UnsafeRawPointer) {
            address = withPtr.assumingMemoryBound(to: UInt64.self).pointee
            modTime = withPtr.advanced(by: 8).assumingMemoryBound(to: UInt64.self).pointee
            inode = withPtr.advanced(by: 16).assumingMemoryBound(to: UInt64.self).pointee
            pathFileOffset = withPtr.advanced(by: 24).assumingMemoryBound(to: UInt32.self).pointee
            pad = withPtr.advanced(by: 28).assumingMemoryBound(to: UInt32.self).pointee
            
            path = String(cString: base.advanced(by: Int(pathFileOffset)).assumingMemoryBound(to: Int8.self))
        }
    }
    
    public struct AcceleratorInfo {
        public var initializers: [InitInfo] = []
        
        public init() {}
        
        public init(withPtr: UnsafeRawPointer) {
            let initOffset = withPtr.advanced(by: 24).assumingMemoryBound(to: UInt32.self).pointee
            let initCount = withPtr.advanced(by: 24).assumingMemoryBound(to: UInt32.self).pointee
            
            var cur = withPtr.advanced(by: Int(initOffset))
            for _ in 0..<initCount {
                initializers.append(InitInfo(withPtr: cur))
                cur = cur.advanced(by: 8)
            }
        }
        
        public struct InitInfo {
            public var functionOffset: UInt32 = 0
            public var imageNumber: UInt32 = 0
            
            public init() {}
            
            public init(withPtr: UnsafeRawPointer) {
                functionOffset = withPtr.assumingMemoryBound(to: UInt32.self).pointee
                imageNumber = withPtr.advanced(by: 4).assumingMemoryBound(to: UInt32.self).pointee
            }
        }
    }
}
