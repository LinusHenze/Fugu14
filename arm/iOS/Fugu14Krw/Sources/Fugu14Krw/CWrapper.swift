//
//  CWrapper.swift
//  Fugu15Krw
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import JailbreakUtils
import KernelExploit
import LibKRW_Plugin

var gMemoryAccess: MemoryAccess!

@_cdecl("krw_initializer")
public func krw_initializer(_ handlers: krw_handlers_t) -> Int32 {
    if gMemoryAccess == nil {
        do {
            gMemoryAccess = try initFugu15Krw()
        } catch {
            return EPERM
        }
    }
    
    handlers.pointee.version = UInt64(LIBKRW_HANDLERS_VERSION)
    handlers.pointee.kbase = { base in
        base!.pointee = gMemoryAccess.kernelVirtBase
        return 0
    }
    handlers.pointee.kread = { from, to, size in
        do {
            let data = try gMemoryAccess.readBytes(virt: from, count: UInt64(size))
            data.copyBytes(to: to!.assumingMemoryBound(to: UInt8.self), count: size)
            
            return 0
        } catch {
            // Also zero memory
            bzero(to!, size)
            
            return EINVAL
        }
    }
    handlers.pointee.kwrite = { from, to, size in
        do {
            let data = Data(bytesNoCopy: from!, count: size, deallocator: .none)
            try gMemoryAccess.writeBytes(virt: to, data: data)
            
            return 0
        } catch {
            return EINVAL
        }
    }
    
    return 0
}
