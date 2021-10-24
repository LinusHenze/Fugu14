//
//  main.swift
//  jailbreakd
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import KernelExploit
import externalCStuff
import asmAndC

// Note: I never tested the fast untether on a real device
//       Enabling it may bootloop your device and force you to update it
// !!!         I STRONGLY ADVISE AGAINST ENABLING THE FAST UNTETHER         !!!
// !!! IF IT BREAKS YOUR DEVICE, I WILL TAKE *ABSOLUTELY NO RESPONSIBILITY* !!!
let fastUntetherEnabled = false

// AltStore builds should have this option set to true
// This will cause a message to be shown after installing the untether
let altStoreBuild       = false

var pe: PostExploitation!

@_cdecl("init_libkrw_support")
func init_libkrw_support() -> Int32 {
    guard pe != nil else {
        return 999
    }
    
    return pe!.initKrwSupport()
}

@discardableResult
func run(prog: String, args: [String]) -> Bool {
    var argv = [strdup(prog)]
    for a in args {
        argv.append(strdup(a))
    }
    
    argv.append(nil)
    
    defer { for a in argv { if a != nil { free(a) } } }
    
    typealias fType = @convention(c) () -> pid_t
    let fork = unsafeBitCast(dlsym(dlopen(nil, 0), "fork"), to: fType.self)
    let child: pid_t = fork()
    if child == 0 {
        execv(prog, &argv)
        puts("Failed to exec: \(String(cString: strerror(errno)))")
        exit(-1)
    }
    
    waitpid(child, nil, 0)
    return true
}

@discardableResult
func runWithKCreds(pe: PostExploitation, prog: String, args: [String]) -> Bool {
    var argv = [strdup(prog)]
    for a in args {
        argv.append(strdup(a))
    }
    
    argv.append(nil)
    
    defer { for a in argv { if a != nil { free(a) } } }
    
    var spawnattr: posix_spawnattr_t?
    posix_spawnattr_init(&spawnattr)
    posix_spawnattr_setflags(&spawnattr, Int16(POSIX_SPAWN_START_SUSPENDED))
    
    var child: pid_t = 0
    let res = posix_spawn(&child, prog, nil, &spawnattr, argv, environ)
    if res != 0 {
        return false
    }
    
    usleep(10000)
    var cur = Proc.getFirstProc(pe: pe)
    while cur != nil {
        if cur.unsafelyUnwrapped.pid == child {
            Logger.print("Found child, giving creds")
            let res = (try? pe.giveKernelCreds(toProc: cur.unsafelyUnwrapped)) == nil ? false : true
            Logger.print("Status: \(res)")
            
            break
        }
        
        cur = cur.unsafelyUnwrapped.next
    }
    
    kill(child, SIGCONT)
    
    waitpid(child, nil, 0)
    return true
}

@discardableResult
func showMessage(withOptions options: [CFString: NSObject]) -> CFOptionFlags {
    while true {
        var err: Int32 = 0
        let notif = CFUserNotificationCreate(kCFAllocatorDefault, 0, kCFUserNotificationPlainAlertLevel, &err, options as CFDictionary)
        guard notif != nil && err == 0 else {
            sleep(1)
            continue
        }
        
        var response: CFOptionFlags = 0
        CFUserNotificationReceiveResponse(notif, 0, &response)
        
        guard (response & 0x3) != kCFUserNotificationCancelResponse else {
            sleep(1)
            continue
        }
        
        return response & 0x3
    }
}

func showSimpleMessage(withTitle title: String, andMessage message: String) {
    showMessage(withOptions: [
        kCFUserNotificationAlertTopMostKey: 1 as NSNumber,
        kCFUserNotificationAlertHeaderKey: title as NSString,
        kCFUserNotificationAlertMessageKey: message as NSString
    ])
}

func doInstall(pe: PostExploitation) {
    let result = pe.install()
    
    switch result {
    case .rebootRequired:
        showMessage(withOptions: [
            kCFUserNotificationAlertTopMostKey: 1 as NSNumber,
            kCFUserNotificationAlertHeaderKey: "Reboot required" as NSString,
            kCFUserNotificationAlertMessageKey: "Fugu14 successfully installed the untether. To complete the installation, your device needs to be rebooted." as NSString,
            kCFUserNotificationDefaultButtonTitleKey: "Reboot now" as NSString
        ])
        
        reboot(0)
        exit(0)
        
    case .ok:
        showSimpleMessage(withTitle: "Already installed", andMessage: "Fugu14 has already been installed. Please restore the root fs if you're experienceing any problems.")
        exit(0)
    
    case .otaAlreadyMounted:
        showSimpleMessage(withTitle: "OTA already mounted", andMessage: "Fugu14 could not be installed because an OTA update is already mounted. Please remove the update, reboot and run the installer again.")
        exit(0)
        
    case .failed(reason: let reason):
        showSimpleMessage(withTitle: "Failed to install untether", andMessage: "The untether failed to install. Error: \(reason)")
        exit(0)
    }
}

func doUninstall() {
    let result = PostExploitation.uninstall()
    
    switch result {
    case .rebootRequired:
        showMessage(withOptions: [
            kCFUserNotificationAlertTopMostKey: 1 as NSNumber,
            kCFUserNotificationAlertHeaderKey: "Reboot required" as NSString,
            kCFUserNotificationAlertMessageKey: "To complete the uninstallation of Fugu14, your device needs to be rebooted." as NSString,
            kCFUserNotificationDefaultButtonTitleKey: "Reboot now" as NSString
        ])
        
        reboot(0)
        exit(0)
        
    case .noRestoreRequired:
        showSimpleMessage(withTitle: "Not installed", andMessage: "Fugu14 could not be uninstalled because it is not installed.")
        exit(0)
    
    case .failed(reason: let reason):
        showSimpleMessage(withTitle: "Failed to uninstall", andMessage: "Fugu14 could not be uninstalled. Error: \(reason)")
        exit(0)
    }
}

func doSilentUninstall() {
    let result = PostExploitation.uninstall()
    
    switch result {
    case .rebootRequired:
        reboot(0)
    default:
        break
    }
}

func serverMain(pe: PostExploitation) -> Never {
    let controlIn = FileHandle(fileDescriptor: Int32(CommandLine.arguments[2])!, closeOnDealloc: true)
    let controlOut = FileHandle(fileDescriptor: Int32(CommandLine.arguments[3])!, closeOnDealloc: true)
    
    let comm = ProcessCommunication(read: controlIn, write: controlOut)
    
    while true {
        guard let cmd = comm.receiveArg() else {
            // Probably broken pipe
            exit(-1)
        }
        
        switch cmd {
        case "ping":
            comm.sendArg("pong")
            
        case "install":
            Logger.print("Received install request!")
            doInstall(pe: pe)
            
        case "uninstall":
            Logger.print("Received uninstall request!")
            doUninstall()
            
        default:
            Logger.print("Received unknown command \(cmd)!")
        }
    }
}

if getuid() != 0 {
    // Not root, UI Process
    // Do UI stuff
    // Remove old closures first
    let cacheDir = String(cString: getenv("HOME")) + "/Library/Caches/com.apple.dyld"
    if let closures = try? FileManager.default.contentsOfDirectory(atPath: cacheDir) {
        for c in closures {
            if c != "." && c != ".." && !c.hasSuffix(".closure") {
                try? FileManager.default.removeItem(at: URL(fileURLWithPath: c, relativeTo: URL(fileURLWithPath: cacheDir)))
            }
        }
    }
    
    JailbreakdApp.main()
    
    fatalError("AppDelegate.main() returned!")
}

if CommandLine.arguments.count < 2 {
    Logger.print("Didn't receive any arguments, I don't know what to do!")
    fatalError("Didn't receive any arguments, I don't know what to do!")
}

var action = CommandLine.arguments[1]
if action == "ping" {
    // Launched from App only to attach signature
    // Do nothing
    Logger.print("pong")
    exit(0)
} else if action == "uninstall" {
    doUninstall()
    exit(0)
} else if action == "doNothing" {
    dispatchMain()
} else if action != "server" {
    setsid()
} else {
    let logOut = FileHandle(fileDescriptor: Int32(CommandLine.arguments[4])!, closeOnDealloc: true)
    Logger.logFileHandle = logOut
}

if action == "untether" {
    if access("/", W_OK) == 0 {
        // Untether already ran, sleep forever
        // Try to replace service to prevent us from being launched again
        if !fastUntetherEnabled {
            run(prog: "/.Fugu14Untether/bin/launchctl", args: ["unload", "/System/Library/LaunchDaemons/com.apple.analyticsd.plist"])
            run(prog: "/.Fugu14Untether/bin/launchctl", args: ["load",   "/Library/LaunchDaemons/com.apple.analyticsd.plist"])
        }
        
        dispatchMain()
    }
    
    let state = getUntetherState()
    if state == .disabled {
        // Sleep forever
        dispatchMain()
    } else if state == .forceRestore {
        action = "silent_uninstall"
    }
}

do {
    pe = try PostExploitation()
} catch MemoryAccessError.failedToInitialize {
    execv(Bundle.main.executablePath, CommandLine.unsafeArgv)
    fatalError("Failed to re-exec myself!")
} catch let e {
    Logger.print("Failed to initialize a PostExploitation object")
    Logger.print("Error: \(e)")
    fatalError("Error: \(e)")
}

switch action {
case "untether":
    // First of all, inject trust cache
    pe.unsafelyUnwrapped.injectTC(path: "/.Fugu14Untether/trustcache")
    
    // Now replace service
    if !fastUntetherEnabled {
        run(prog: "/.Fugu14Untether/bin/launchctl", args: ["unload", "/System/Library/LaunchDaemons/com.apple.analyticsd.plist"])
        run(prog: "/.Fugu14Untether/bin/launchctl", args: ["load",   "/Library/LaunchDaemons/com.apple.analyticsd.plist"])
    }
    
    // Attempt to mount, then launch jailbreak server
    if case .ok = pe.unsafelyUnwrapped.untether() {
        do {
            // See if we should load custom trust caches
            if let autorun = try? FileManager.default.contentsOfDirectory(atPath: "/.Fugu14Untether/trustcaches/") {
                for exe in autorun {
                    let path = "/.Fugu14Untether/trustcaches/" + exe
                    if access(path, R_OK) == 0 {
                        // Inject it
                        pe.unsafelyUnwrapped.injectTC(path: path)
                    }
                }
            }
            
            // See if we have any autorun executables
            if let autorun = try? FileManager.default.contentsOfDirectory(atPath: "/.Fugu14Untether/autorun/") {
                for exe in autorun {
                    let path = "/.Fugu14Untether/autorun/" + exe
                    if access(path, X_OK) == 0 {
                        // Execute it
                        var child: pid_t = 0
                        _ = path.withCString { cPath in
                            posix_spawn(&child, path, nil, nil, [UnsafeMutablePointer<CChar>(mutating: cPath), nil], environ)
                        }
                    }
                }
            }
            
            // Deinit kernel call, not required anymore
            pe.unsafelyUnwrapped.deinitKernelCall()
            
            // Check if we should show AltStore message
            if access("/.Fugu14Untether/.AltStoreInstall", F_OK) == 0 {
                showSimpleMessage(withTitle: "Untether installed", andMessage: "To continue installing your jailbreak, please open AltStore and follow the instructions.")
                unlink("/.Fugu14Untether/.AltStoreInstall")
            }
            
            // Also launch iDownload
            launchCServer()
            dispatchMain()
        } /*catch let e {
            Logger.print("Failed to start server: \(e)")
        }*/
    } else {
        Logger.print("Remount failed!")
    }
    
case "uninstall":
    // Restore RootFS and remove other stuff
    doUninstall()
    
case "silent_uninstall":
    doSilentUninstall()
    dispatchMain()

case "server":
    serverMain(pe: pe.unsafelyUnwrapped)
    
// Stuff below is useful on the SRD
case "install":
    doInstall(pe: pe.unsafelyUnwrapped)

case "remount":
    pe.unsafelyUnwrapped.mountOnly()

case "loadTC":
    if CommandLine.arguments.count < 3 {
        Logger.print("Usage: jailbreakd loadTC <path_to_trust_cache>")
        exit(-1)
    }
    pe.unsafelyUnwrapped.injectTC(path: CommandLine.arguments[2])
    pe.unsafelyUnwrapped.deinitKernelCall()
    
default:
    Logger.print("Unknown action \(action)!")
}

pe.unsafelyUnwrapped.killMe()
