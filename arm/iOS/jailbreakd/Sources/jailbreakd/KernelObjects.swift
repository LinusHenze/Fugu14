//
//  KernelObjects.swift
//  jailbreakd
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import KernelExploit

class KernelObject {
    let pe: PostExploitation
    let addr: UInt64
    
    init?(_ pe: PostExploitation, addr: UInt64?) {
        if addr == nil || addr.unsafelyUnwrapped == 0 {
            return nil
        }
        
        self.pe = pe
        self.addr = addr.unsafelyUnwrapped
    }
}

class SpecInfo: KernelObject {
    var flags: UInt32 {
        get {
            return (try? pe.mem.r32(virt: addr + pe.offsets.specinfoStruct.flags)) ?? 0
        }
        set {
            try? pe.mem.w32(virt: addr + pe.offsets.specinfoStruct.flags, data: newValue)
        }
    }
}

class MountStruct: KernelObject, Sequence {
    typealias Iterator = MountStructIterator
    
    class MountStructIterator: IteratorProtocol {
        typealias Element = MountStruct
        
        var cur: MountStruct?
        let pe:  PostExploitation
        
        init(_ ms: MountStruct) {
            cur = ms
            pe  = ms.pe
        }
        
        func next() -> Element? {
            if cur != nil {
                if let addr = try? pe.mem.rPtr(virt: cur!.addr + pe.offsets.mountStruct.next) {
                    let new = MountStruct(pe, addr: addr)
                    cur = new
                    return new
                }
            }
            
            return nil
        }
    }
    
    var devvp: VNode? {
        if let addr = try? pe.mem.rPtr(virt: addr + pe.offsets.mountStruct.devvp) {
            return VNode(pe, addr: addr)
        }
        
        return nil
    }
    var vnodelist: VNode? {
        if let addr = try? pe.mem.rPtr(virt: addr + pe.offsets.mountStruct.vnodelist) {
            return VNode(pe, addr: addr)
        }
        
        return nil
    }
    var flags: Int32 {
        get {
            return Int32(bitPattern: (try? pe.mem.r32(virt: addr + pe.offsets.mountStruct.flags)) ?? 0)
        }
        set {
            try? pe.mem.w32(virt: addr + pe.offsets.mountStruct.flags, data: UInt32(bitPattern: newValue))
        }
    }
    
    func makeIterator() -> Iterator {
        return MountStructIterator(self)
    }
}

class APFSData: KernelObject {
    var flags: UInt32 {
        get {
            return (try? pe.mem.r32(virt: addr + pe.offsets.apfsStruct.flags)) ?? 0
        }
        set {
            try? pe.mem.w32(virt: addr + pe.offsets.apfsStruct.flags, data: newValue)
        }
    }
}

class VNode: KernelObject, Sequence {
    typealias Iterator = VNodeIterator
    
    class VNodeIterator: IteratorProtocol {
        typealias Element = VNode
        
        var cur: VNode?
        let pe:  PostExploitation
        
        init(_ vnode: VNode) {
            cur = vnode
            pe  = vnode.pe
        }
        
        func next() -> Element? {
            if cur != nil {
                if let addr = try? pe.mem.rPtr(virt: cur!.addr + pe.offsets.vnodeStruct.nextInList) {
                    let new = VNode(pe, addr: addr)
                    cur = new
                    return new
                }
            }
            
            return nil
        }
    }
    
    var name: String {
        do {
            return try pe.mem.rStr(virt: try pe.mem.rPtr(virt: addr + pe.offsets.vnodeStruct.name))
        } catch _ {
            return ""
        }
    }
    var parent: VNode? {
        if let addr = try? pe.mem.rPtr(virt: addr + pe.offsets.vnodeStruct.parent) {
            return VNode(pe, addr: addr)
        }
        
        return nil
    }
    var specInfo: SpecInfo? {
        if let addr = try? pe.mem.rPtr(virt: addr + pe.offsets.vnodeStruct.specinfo) {
            return SpecInfo(pe, addr: addr)
        }
        
        return nil
    }
    var mount: MountStruct? {
        if let addr = try? pe.mem.rPtr(virt: addr + pe.offsets.vnodeStruct.mount) {
            return MountStruct(pe, addr: addr)
        }
        
        return nil
    }
    var data: APFSData? {
        if let addr = try? pe.mem.rPtr(virt: addr + pe.offsets.vnodeStruct.data) {
            return APFSData(pe, addr: addr)
        }
        
        return nil
    }
    
    func makeIterator() -> Iterator {
        return VNodeIterator(self)
    }
}

class Pmap: KernelObject {
    var ttep: UInt64 {
        get {
            (try? pe.mem.r64(virt: addr + pe.offsets.pmapStruct.ttepOffset)) ?? 0
        }
        
        set {
            try? pe.mem.w64(virt: addr + pe.offsets.pmapStruct.ttepOffset, data: newValue)
        }
    }
}

class VmMap: KernelObject {
    var pmap: Pmap? {
        Pmap(pe, addr: try? pe.mem.rPtr(virt: addr + pe.offsets.vmMapStruct.pmapOffset))
    }
}

class Thread: KernelObject {
    var next: Thread? {
        Thread(pe, addr: try? pe.mem.r64(virt: addr + pe.offsets.threadStruct.nextOffset))
    }
    var machine: UInt64 {
        (try? pe.mem.r64(virt: addr + pe.offsets.threadStruct.nextOffset)) ?? 0
    }
}

class ITKSpace: KernelObject {
    var is_table: UInt64? {
        try? pe.mem.rPtr(virt: addr + pe.offsets.itkSpaceStruct.is_table)
    }
}

class Task: KernelObject {
    var thread: Thread? {
        Thread(pe, addr: try? pe.mem.r64(virt: addr + pe.offsets.taskStruct.threadOffset))
    }
    var thCount: UInt32 {
        (try? pe.mem.r32(virt: addr + pe.offsets.taskStruct.threadCountOffset)) ?? 0
    }
    var vmMap: VmMap? {
        VmMap(pe, addr: try? pe.mem.rPtr(virt: addr + pe.offsets.taskStruct.vmMapOffset))
    }
    var itk_space: ITKSpace? {
        ITKSpace(pe, addr: try? pe.mem.rPtr(virt: addr + pe.offsets.taskStruct.itk_space))
    }
}

class Ucred: KernelObject {
    var cr_uid: UInt32? {
        try? pe.mem.r32(virt: addr + pe.offsets.ucredStruct.cr_uid)
    }
    var cr_svuid: UInt32? {
        get {
            try? pe.mem.r32(virt: addr + pe.offsets.ucredStruct.cr_svuid)
        }
        set {
            if let nv = newValue {
                try? pe.mem.w32(virt: addr + pe.offsets.ucredStruct.cr_svuid, data: nv)
            }
        }
    }
    var label: UInt64? {
        try? pe.mem.rPtr(virt: addr + pe.offsets.ucredStruct.label)
    }
}

enum ProcError: Error {
    case noPageTable
}

class Proc: KernelObject {
    var next: Proc? {
        Proc(pe, addr: try? pe.mem.r64(virt: addr + pe.offsets.procStruct.nextOffset))
    }
    var pid: UInt32 {
        // Don't return 0 on failure, 0 would be the kernel task
        (try? pe.mem.r32(virt: addr + pe.offsets.procStruct.pidOffset)) ?? UINT32_MAX
    }
    var task: Task? {
        Task(pe, addr: try? pe.mem.rPtr(virt: addr + pe.offsets.procStruct.taskOffset))
    }
    var ucred: Ucred? {
        Ucred(pe, addr: try? pe.mem.rPtr(virt: addr + pe.offsets.procStruct.ucred))
    }
    var textvp: VNode? {
        VNode(pe, addr: try? pe.mem.rPtr(virt: addr + pe.offsets.procStruct.textvp))
    }
    
    var csFlags: UInt32? {
        get {
            try? pe.mem.r32(virt: addr + pe.offsets.procStruct.csFlagsOffset)
        }
        
        set {
            try? pe.mem.w32(virt: addr + pe.offsets.procStruct.csFlagsOffset, data: newValue ?? 0)
        }
    }
    
    static func getFirstProc(pe: PostExploitation) -> Proc? {
        let allproc = try? pe.mem.r64(virt: pe.slide(pe.offsets.allProcAddr))
        
        return Proc(pe, addr: allproc)
    }
    
    func virt2phys(_ virt: UInt64) throws -> UInt64 {
        guard let ttep = task?.vmMap?.pmap?.ttep else {
            throw ProcError.noPageTable
        }
        
        return try pe.mem.walkPageTable(table: ttep, virt: virt)
    }
    
    private func _readBytes(virt: UInt64, count: UInt64, prev: Data? = nil) throws -> Data {
        // This should be a recursive function, but Swift's tail call optimization is really bad
        var virt = virt
        var count = count
        var prev = prev
        while true {
            if count == 0 {
                return Data()
            }
            
            // Get physical address for this page
            let phys = try virt2phys(virt)
            
            // Check if address + count spans multiple pages
            let startPage = virt & ~0x3FFF
            let endPage   = (virt + (count - 1)) & ~0x3FFF
            if startPage != endPage {
                // Multiple pages
                // This requires multiple lookups
                // Read the start page first
                let bytesToRead = 0x4000 - (startPage & 0x3FFF)
                
                var read = try pe.mem.readBytes(phys: phys, count: bytesToRead)
                if prev != nil {
                    // Have previous data, prepend it
                    read = prev.unsafelyUnwrapped + read
                }
                
                // Read the rest, recursively
                virt = virt + bytesToRead
                count = count - bytesToRead
                prev = read
                continue
            }
            
            // Only a single page, this is easy
            var res = try pe.mem.readBytes(phys: phys, count: count)
            if prev != nil {
                res = prev.unsafelyUnwrapped + res
            }
            
            return res
        }
    }
    
    func readBytes(virt: UInt64, count: UInt64) throws -> Data {
        return try _readBytes(virt: virt, count: count)
    }
    
    func writeBytes(virt: UInt64, data: Data) throws {
        if data.count == 0 {
            return
        }
        
        // Get physical address for this page
        let phys = try virt2phys(virt)
        
        // Check if address + count spans multiple pages
        let startPage = virt & ~0x3FFF
        let endPage   = (virt + UInt64(data.count - 1)) & ~0x3FFF
        if startPage != endPage {
            // Multiple pages
            // This requires multiple lookups
            // Write to the start page first
            let bytesToWrite = 0x4000 - (startPage & 0x3FFF)
            
            let subdata = data[0..<Int(bytesToWrite)]
            try pe.mem.writeBytes(phys: phys, data: subdata)
            
            // Write the rest, recursively
            return try writeBytes(virt: virt + bytesToWrite, data: data[Int(bytesToWrite)...])
        }
        
        // Only a single page, this is easy
        try pe.mem.writeBytes(phys: phys, data: data)
    }
    
    func r64(virt: UInt64) throws -> UInt64 {
        return try readBytes(virt: virt, count: 8).getGeneric(type: UInt64.self)
    }
    
    func r32(virt: UInt64) throws -> UInt32 {
        return try readBytes(virt: virt, count: 4).getGeneric(type: UInt32.self)
    }
    
    func r16(virt: UInt64) throws -> UInt16 {
        return try readBytes(virt: virt, count: 2).getGeneric(type: UInt16.self)
    }
    
    func r8(virt: UInt64) throws -> UInt8 {
        return try readBytes(virt: virt, count: 1).getGeneric(type: UInt8.self)
    }
    
    func w64(virt: UInt64, data: UInt64) throws {
        let dat = Data(fromObject: data)
        try writeBytes(virt: virt, data: dat)
    }
    
    func w32(virt: UInt64, data: UInt32) throws {
        let dat = Data(fromObject: data)
        try writeBytes(virt: virt, data: dat)
    }
    
    func w16(virt: UInt64, data: UInt16) throws {
        let dat = Data(fromObject: data)
        try writeBytes(virt: virt, data: dat)
    }
    
    func w8(virt: UInt64, data: UInt8) throws {
        let dat = Data(fromObject: data)
        try writeBytes(virt: virt, data: dat)
    }
}
