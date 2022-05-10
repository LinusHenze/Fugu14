//
//  installUntether.swift
//  jailbreakd
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import ClosurePwn
import JailbreakUtils

// If something has "ps" in it's name, it's actually ReportCrash
// I've used ps before, but 14.5 broke it (can only use task ports for reading)

let untetherContainerPath   = "/private/var/mobile/Containers/Data/Fugu14Untether"
let untetherClFolder        = "/private/var/Fugu14UntetherDYLD"
let untetherClPathAnalytics = untetherClFolder + "/Caches/com.apple.dyld/analyticsd.closure"
let untetherClPathLogd      = untetherClFolder + "/Caches/com.apple.dyld/logd.closure"
let untetherClPathPs        = untetherClFolder + "/Caches/com.apple.dyld/stage2.closure"

enum UntetherInstallError: Error {
    case failedToLocateJailbreakd
    case triedToUpdateFastUntetherWhichIsNotSupportedRestoreRootfsInstead
}

func ensureNoDataProtection(_ url: URL) throws {
    try FileManager.default.setAttributes([.protectionKey: FileProtectionType.none], ofItemAtPath: url.path)
}

func ensureNoDataProtection(_ path: String) throws {
    try FileManager.default.setAttributes([.protectionKey: FileProtectionType.none], ofItemAtPath: path)
}

func installSlowUntether(mountPath: String, trustcache: String, isUpdate: Bool) throws {
    guard let exePath = Bundle.main.executablePath else {
        throw UntetherInstallError.failedToLocateJailbreakd
    }
    
    let targetUGID = 263
    let targetExePath = mountPath + "/System/Library/PrivateFrameworks/CoreAnalytics.framework/Support/analyticsd"
    let replacementExePath = "/usr/libexec/keybagd"
    
    Logger.print("Installing the Fugu14 untether")
    
    guard access(untetherClPathLogd, F_OK) != 0 else {
        // !!!
        // Someone has the *fast* untether installed?!
        // Throw an error immediately
        Logger.print("!!! ATTEMPTED TO UPDATE FAST UNTETHER !!!")
        Logger.print("!!! THIS IS NOT SUPPORTED FOR SAFETY !!!")
        Logger.print("!!! PLEASE RESTORE ROOTFS !!!")
        throw UntetherInstallError.triedToUpdateFastUntetherWhichIsNotSupportedRestoreRootfsInstead
    }
    
    chflags(untetherClPathAnalytics, 0)
    unlink(untetherClPathAnalytics)
    chflags(untetherClPathLogd, 0)
    unlink(untetherClPathLogd)
    chflags(untetherClPathPs, 0)
    unlink(untetherClPathPs)
    
    Logger.print("Creating container files...")
    
    try? FileManager.default.removeItem(atPath: untetherClFolder)
    try? FileManager.default.removeItem(atPath: untetherContainerPath)
    
    try FileManager.default.createDirectory(atPath: untetherContainerPath, withIntermediateDirectories: true, attributes: [.ownerAccountID: targetUGID, .groupOwnerAccountID: targetUGID])
    try FileManager.default.createDirectory(atPath: untetherClFolder + "/Caches/com.apple.dyld", withIntermediateDirectories: true, attributes: [.ownerAccountID: targetUGID, .groupOwnerAccountID: targetUGID])
    try? FileManager.default.createSymbolicLink(atPath: untetherContainerPath + "/Library", withDestinationPath: untetherClFolder)
    
    Logger.print("Writing JS files")
    try? FileManager.default.createDirectory(atPath: mountPath + "/.Fugu14Untether", withIntermediateDirectories: false, attributes: nil)
    try? FileManager.default.removeItem(atPath: mountPath + "/.Fugu14Untether/stage2")
    try FileManager.default.createSymbolicLink(atPath: mountPath + "/.Fugu14Untether/stage2", withDestinationPath: "/System/Library/CoreServices/ReportCrash")
    try jsUtilsData.write(toFile: mountPath + "/.Fugu14Untether/utils.js", atomically: false, encoding: .utf8)
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/utils.js")
    try jsSetupData.write(toFile: mountPath + "/.Fugu14Untether/setup.js", atomically: false, encoding: .utf8)
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/setup.js")
    try jsKernelExploitLauncherData.write(toFile: mountPath + "/.Fugu14Untether/launchKernelExploit.js", atomically: false, encoding: .utf8)
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/launchKernelExploit.js")
    
    Logger.print("Writing untether binary")
    try? FileManager.default.removeItem(atPath: mountPath + "/.Fugu14Untether/jailbreakd")
    try FileManager.default.copyItem(atPath: exePath, toPath: mountPath + "/.Fugu14Untether/jailbreakd")
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/jailbreakd")
    
    Logger.print("Writing trust cache")
    try? FileManager.default.removeItem(atPath: mountPath + "/.Fugu14Untether/trustcache")
    try FileManager.default.copyItem(atPath: trustcache, toPath: mountPath + "/.Fugu14Untether/trustcache")
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/trustcache")
    
    Logger.print("Writing exploit")
    let datAnalytics = try! KeybagClosure(name: "Fugu14Untether").getClosure().emit()
    try datAnalytics.write(to: URL(fileURLWithPath: untetherClPathAnalytics))
    try ensureNoDataProtection(untetherClPathAnalytics)
    chflags(untetherClPathAnalytics, __uint32_t(UF_IMMUTABLE | SF_IMMUTABLE))
    
    let datPs = try! PSClosure(name: "Fugu14Untether-Stage2").getClosure().emit()
    try datPs.write(to: URL(fileURLWithPath: untetherClPathPs))
    try ensureNoDataProtection(untetherClPathPs)
    chflags(untetherClPathPs, __uint32_t(UF_IMMUTABLE | SF_IMMUTABLE))
    
    if !isUpdate {
        Logger.print("Setting HOME")
        let masterPasswd = try! String(contentsOf: URL(fileURLWithPath: "/etc/master.passwd"))
        if !masterPasswd.contains("_nanalyticsd") {
            let lines = masterPasswd.split(separator: "\n")
            var nMasterPasswd = ""
            for line in lines {
                if line.starts(with: "_analyticsd") {
                    nMasterPasswd.append(line.replacingOccurrences(of: "_analyticsd", with: "_nanalyticsd") + "\n")
                    nMasterPasswd.append("_analyticsd:*:263:263::0:0:Haxx Daemon:" + untetherContainerPath + ":/usr/bin/false\n")
                } else {
                    nMasterPasswd.append(line + "\n")
                }
            }
            
            try nMasterPasswd.write(toFile: mountPath + "/etc/master.passwd", atomically: true, encoding: .utf8)
            try ensureNoDataProtection(mountPath + "/etc/master.passwd")
        }
        
        let passwd = try! String(contentsOf: URL(fileURLWithPath: "/etc/passwd"))
        if !passwd.contains("_nanalyticsd") {
            let lines = passwd.split(separator: "\n")
            var nPasswd = ""
            for line in lines {
                if line.starts(with: "_analyticsd") {
                    nPasswd.append(line.replacingOccurrences(of: "_analyticsd", with: "_nanalyticsd") + "\n")
                    nPasswd.append("_analyticsd:*:263:263:Haxx Daemon:" + untetherContainerPath + ":/usr/bin/false\n")
                    
                } else {
                    nPasswd.append(line + "\n")
                }
            }
            
            try nPasswd.write(toFile: mountPath + "/etc/passwd", atomically: true, encoding: .utf8)
            try ensureNoDataProtection(mountPath + "/etc/passwd")
        }
    }
    
    Logger.print("Replacing target")
    if access(targetExePath + ".back", F_OK) != 0 {
        print("Backing up target")
        try FileManager.default.moveItem(atPath: targetExePath, toPath: targetExePath + ".back")
        try ensureNoDataProtection(targetExePath + ".back")
    }
    
    try? FileManager.default.removeItem(atPath: targetExePath)
    try FileManager.default.copyItem(atPath: replacementExePath, toPath: targetExePath)
    try ensureNoDataProtection(targetExePath)
    
    Logger.print("Successfully installed untether!")
    
    // Also create trustcaches and autorun folder
    try? FileManager.default.createDirectory(atPath: mountPath + "/.Fugu14Untether/trustcaches", withIntermediateDirectories: false, attributes: nil)
    try? FileManager.default.createDirectory(atPath: mountPath + "/.Fugu14Untether/autorun", withIntermediateDirectories: false, attributes: nil)
}

func installFastUntether(mountPath: String, trustcache: String, isUpdate: Bool) throws {
    if isUpdate {
        Logger.print("!!! ATTEMPTED TO UPDATE FAST UNTETHER !!!")
        Logger.print("!!! THIS IS NOT SUPPORTED FOR SAFETY !!!")
        Logger.print("!!! PLEASE RESTORE ROOTFS !!!")
        throw UntetherInstallError.triedToUpdateFastUntetherWhichIsNotSupportedRestoreRootfsInstead
    }
    
    guard let exePath = Bundle.main.executablePath else {
        throw UntetherInstallError.failedToLocateJailbreakd
    }
    
    let targetUGID = 272
    let targetExePath = mountPath + "/usr/libexec/logd"
    let replacementExePath = "/usr/libexec/keybagd"

    Logger.print("Installing the Fugu14 untether")

    chflags(untetherClPathAnalytics, 0)
    unlink(untetherClPathAnalytics)
    chflags(untetherClPathLogd, 0)
    unlink(untetherClPathLogd)
    chflags(untetherClPathPs, 0)
    unlink(untetherClPathPs)

    Logger.print("Creating container files...")

    try? FileManager.default.removeItem(atPath: untetherContainerPath)
    try? FileManager.default.removeItem(atPath: untetherClFolder)

    try FileManager.default.createDirectory(atPath: untetherContainerPath, withIntermediateDirectories: true, attributes: [.ownerAccountID: targetUGID, .groupOwnerAccountID: targetUGID])
    try FileManager.default.createDirectory(atPath: untetherClFolder + "/Caches/com.apple.dyld", withIntermediateDirectories: true, attributes: [.ownerAccountID: targetUGID, .groupOwnerAccountID: targetUGID])
    try FileManager.default.createSymbolicLink(atPath: untetherContainerPath + "/Library", withDestinationPath: untetherClFolder)

    Logger.print("Writing JS files")
    try? FileManager.default.createDirectory(atPath: mountPath + "/.Fugu14Untether", withIntermediateDirectories: false, attributes: nil)
    try FileManager.default.createSymbolicLink(atPath: mountPath + "/.Fugu14Untether/stage2", withDestinationPath: "/System/Library/CoreServices/ReportCrash")
    try jsUtilsData.write(toFile: mountPath + "/.Fugu14Untether/utils.js", atomically: false, encoding: .utf8)
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/utils.js")
    try jsSetupData.write(toFile: mountPath + "/.Fugu14Untether/setup.js", atomically: false, encoding: .utf8)
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/setup.js")
    try jsKernelExploitLauncherData.write(toFile: mountPath + "/.Fugu14Untether/launchKernelExploit.js", atomically: false, encoding: .utf8)
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/launchKernelExploit.js")
    
    Logger.print("Writing untether binary")
    try FileManager.default.copyItem(atPath: exePath, toPath: mountPath + "/.Fugu14Untether/jailbreakd")
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/jailbreakd")
    
    Logger.print("Writing trust cache")
    try FileManager.default.copyItem(atPath: trustcache, toPath: mountPath + "/.Fugu14Untether/trustcache")
    try ensureNoDataProtection(mountPath + "/.Fugu14Untether/trustcache")

    Logger.print("Writing exploit")
    let kbClosure = try! KeybagClosure(name: "Fugu14Untether")
    kbClosure.fastUntether = true
    let datAnalytics = try! kbClosure.getClosure().emit()
    try datAnalytics.write(to: URL(fileURLWithPath: untetherClPathLogd))
    try ensureNoDataProtection(untetherClPathLogd)
    chflags(untetherClPathLogd, __uint32_t(UF_IMMUTABLE | SF_IMMUTABLE))

    let datPs = try! PSClosure(name: "Fugu14Untether-Stage2").getClosure().emit()
    try datPs.write(to: URL(fileURLWithPath: untetherClPathPs))
    try ensureNoDataProtection(untetherClPathPs)
    chflags(untetherClPathPs, __uint32_t(UF_IMMUTABLE | SF_IMMUTABLE))

    Logger.print("Setting HOME")
    let masterPasswd = try! String(contentsOf: URL(fileURLWithPath: "/etc/master.passwd"))
    var lines = masterPasswd.split(separator: "\n")
    var nMasterPasswd = ""
    for line in lines {
        if line.starts(with: "_logd") {
            nMasterPasswd.append("_logd:*:272:272::0:0:Log Daemon:" + untetherContainerPath + ":/usr/bin/false\n")
        } else {
            nMasterPasswd.append(line + "\n")
        }
    }

    try nMasterPasswd.write(toFile: mountPath + "/etc/master.passwd", atomically: true, encoding: .utf8)
    try ensureNoDataProtection(mountPath + "/etc/master.passwd")

    let passwd = try! String(contentsOf: URL(fileURLWithPath: "/etc/passwd"))
    lines = passwd.split(separator: "\n")
    var nPasswd = ""
    for line in lines {
        if line.starts(with: "_logd") {
            nPasswd.append("_logd:*:272:272:Log Daemon:" + untetherContainerPath + ":/usr/bin/false\n")
        } else {
            nPasswd.append(line + "\n")
        }
    }

    try nPasswd.write(toFile: mountPath + "/etc/passwd", atomically: true, encoding: .utf8)
    try ensureNoDataProtection(mountPath + "/etc/passwd")
    
    Logger.print("Replacing target")
    if access(targetExePath + ".back", F_OK) != 0 {
        print("Backing up target")
        try FileManager.default.moveItem(atPath: targetExePath, toPath: targetExePath + ".back")
        try ensureNoDataProtection(targetExePath + ".back")
    }
    
    try? FileManager.default.removeItem(atPath: targetExePath)
    try FileManager.default.copyItem(atPath: replacementExePath, toPath: targetExePath)
    try ensureNoDataProtection(targetExePath)

    Logger.print("Successfully installed untether!")
    
    // Also create trustcaches and autorun folder
    try? FileManager.default.createDirectory(atPath: mountPath + "/.Fugu14Untether/trustcaches", withIntermediateDirectories: false, attributes: nil)
    try? FileManager.default.createDirectory(atPath: mountPath + "/.Fugu14Untether/autorun", withIntermediateDirectories: false, attributes: nil)
}
