//
//  SharedCacheExt.swift
//  ClosurePwn
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import JailbreakUtils

extension SharedCache {
    public var imageArray: ImageArray? {
        let start = cachePtr.advanced(by: 248).assumingMemoryBound(to: UInt64.self).pointee
        let size = cachePtr.advanced(by: 256).assumingMemoryBound(to: UInt64.self).pointee
        let ptr = UnsafeMutableRawPointer(bitPattern: Int(bitPattern: cachePtr) + Int(start - mappings[0].address))!
        
        return try? ImageArray(fromData: Data(bytesNoCopy: ptr, count: Int(size), deallocator: .none))
    }
    
    public func initBefores(ofImage: String) throws -> InitBefores {
        guard let imArray = imageArray else {
            throw SharedCacheError.noImageArray
        }
        
        let index = try imageNumber(for: ofImage)
        
        return imArray.images[Int(index - 1)].getOrCreateChild(type: 25)
    }
    
    public func dependents(ofImage: String) throws -> Dependents {
        guard let imArray = imageArray else {
            throw SharedCacheError.noImageArray
        }
        
        let index = try imageNumber(for: ofImage)
        
        return imArray.images[Int(index - 1)].getOrCreateChild(type: 15)
    }
    
    public func intOffsetOfPointer(_ ptr: OpaquePointer) throws -> UInt64 {
        let stripped = stripPtr(ptr)
        
        if UInt(bitPattern: stripped) < UInt(bitPattern: cachePtr) {
            throw SharedCacheError.pointerNotInSharedCachePleaseDetachDebuggerAndTryAgain
        }
        
        return UInt64(UInt(bitPattern: stripped) - UInt(bitPattern: cachePtr))
    }
    
    public func intOffsetOfPointer(_ ptr: UnsafeMutableRawPointer) throws -> UInt64 {
        return try intOffsetOfPointer(OpaquePointer(ptr))
    }
    
    public func offsetOfPointer(_ ptr: OpaquePointer) throws -> ResolvedSymbolTarget {
        return .sharedCache(offset: try intOffsetOfPointer(ptr))
    }
    
    public func offsetOfPointer(_ ptr: UnsafeMutableRawPointer) throws -> ResolvedSymbolTarget {
        return try offsetOfPointer(OpaquePointer(ptr))
    }
    
    public func offsetOfSelector(_ selName: String) throws -> ResolvedSymbolTarget {
        typealias RealType     = @convention(c) (_: String) -> Selector
        typealias NewType      = @convention(c) (_: String) -> OpaquePointer?
        
        let real: RealType     = NSSelectorFromString
        let SelectorFromString = unsafeBitCast(real, to: NewType.self)
        
        let ptr = SelectorFromString(selName)
        guard ptr != nil else {
            throw SharedCacheError.selectorNotFound(selector: selName)
        }
        
        return try offsetOfPointer(ptr.unsafelyUnwrapped)
    }

    public func offsetOfObjCClass(_ className: String) throws -> ResolvedSymbolTarget {
        typealias RealType  = @convention(c) (_: String) -> AnyClass?
        typealias NewType   = @convention(c) (_: String) -> OpaquePointer?
        
        let real: RealType  = NSClassFromString
        let ClassFromString = unsafeBitCast(real, to: NewType.self)
        
        let ptr = ClassFromString(className)
        guard ptr != nil else {
            throw SharedCacheError.classNotFound(class: className)
        }
        
        return try offsetOfPointer(ptr.unsafelyUnwrapped)
    }
}
