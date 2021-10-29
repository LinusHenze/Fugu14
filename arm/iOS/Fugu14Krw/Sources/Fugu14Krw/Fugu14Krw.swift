//
//  Fugu14Krw.swift
//  Fugu14Krw
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import Darwin
import JailbreakUtils
import KernelExploit

public enum Fugu14KrwInitError: Error {
    case noServerPort
    case taskInfoFailed
    case noMagicData
    case badMagicData
    case failedToCopyPort
}

public func initFugu14Krw() throws -> MemoryAccess {
    // First get server port
    var svPort: mach_port_t = 0
    var kr = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, HOST_CLOSURED_PORT, &svPort)
    guard kr == KERN_SUCCESS else {
        throw Fugu14KrwInitError.noServerPort
    }
    
    // Find out where the "magic" page is
    var dyldInfo = task_dyld_info()
    var infoCnt = mach_msg_type_number_t(MemoryLayout.size(ofValue: dyldInfo) >> 2)
    kr = withUnsafeMutablePointer(to: &dyldInfo) { ptr in
        task_info(svPort, task_flavor_t(TASK_DYLD_INFO), task_info_t(OpaquePointer(ptr)), &infoCnt)
    }
    
    guard kr == KERN_SUCCESS else {
        throw Fugu14KrwInitError.taskInfoFailed
    }
    
    // Copy address
    let copyFrom = vm_address_t(dyldInfo.all_image_info_addr + 0xFF0)
    var data = Data(count: 0x100)
    var outSize: vm_size_t = 0
    kr = data.withUnsafeMutableBytes { ptr in
        vm_read_overwrite(svPort, copyFrom, vm_size_t(MemoryLayout<vm_address_t>.size), vm_address_t(bitPattern: ptr.baseAddress!), &outSize)
    }
    
    guard kr == KERN_SUCCESS else {
        throw Fugu14KrwInitError.noMagicData
    }
    
    let magicPage = data.getGeneric(type: vm_address_t.self)
    
    // Copy info from "magic" page
    outSize = 0
    kr = data.withUnsafeMutableBytes { ptr in
        vm_read_overwrite(svPort, magicPage, 0x100, vm_address_t(bitPattern: ptr.baseAddress!), &outSize)
    }
     
    guard kr == KERN_SUCCESS else {
        throw Fugu14KrwInitError.noMagicData
    }
    
    func copyPort(offset: UInt) throws -> mach_port_t {
        let raw = data.getGeneric(type: UInt32.self, offset: offset)
        var res: mach_port_t = 0
        var type: mach_msg_type_name_t = 0
        let kr = mach_port_extract_right(svPort, raw, mach_msg_type_name_t(MACH_MSG_TYPE_COPY_SEND), &res, &type)
        guard kr == KERN_SUCCESS else {
            throw Fugu14KrwInitError.failedToCopyPort
        }
        
        return res
    }
    
    // Parse magic data
    let magicValue = data.getGeneric(type: UInt32.self)
    guard magicValue == 0x75677546 else {
        throw Fugu14KrwInitError.badMagicData
    }
    
    let dkSvPort = try copyPort(offset: 0x4)
    let ucPort = try copyPort(offset: 0x8)
    let physMemDesc = try copyPort(offset: 0xC)
    let dmaPort = try copyPort(offset: 0x10)
    let dmaDesc = try copyPort(offset: 0x14)
    let mapAddr = data.getGeneric(type: UInt.self, offset: 0x18)
    
    // Setup krw
    MemoryAccess.setupUsingRawPorts(dkSvPort: dkSvPort, ucPort: ucPort, physMemDesc: physMemDesc, dmaPort: dmaPort, dmaDesc: dmaDesc, mapAddr: mapAddr, remoteTask: svPort)
    
    return try MemoryAccess(noLog: true)
}
