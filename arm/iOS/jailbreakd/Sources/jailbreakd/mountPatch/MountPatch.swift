//
//  MountPatch.swift
//  KernelExploit
//
//  See credits.txt for more information about this file.
//

import Foundation
import KernelExploit
import externalCStuff
import IOKit_iOS

fileprivate let SNAPSHOT_FLAG: UInt32 = 0x40

enum MountResult {
    case ok
    case failed(reason: String)
    case otaAlreadyMounted
    case rebootRequired
}

enum RestoreResult {
    case rebootRequired
    case noRestoreRequired
    case failed(reason: String)
}

enum MountError: Error {
    case failedToCheckForRename
    case failed(error: Int32)
    case failedToFindNewMount
    case failedToClearSnapshotFlag
}

func withFD(file: String, _ callback: (_: Int32) throws -> Bool) rethrows -> Bool {
    let fd = open(file, O_RDONLY)
    if fd == -1 {
        return false
    }
    
    let res = try callback(fd)
    
    close(fd)
    
    return res
}

func getSystemSnapshotName() -> String? {
    let chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen")
    if chosen == 0 {
        return nil
    }
    
    defer { IOObjectRelease(chosen) }
    
    guard let hash = IORegistryEntryCreateCFProperty(chosen, "boot-manifest-hash" as CFString, kCFAllocatorDefault, 0).takeRetainedValue() as? Data else {
        return nil
    }
    
    var bmhStr = ""
    for byte in hash {
        bmhStr += String(format: "%02X", byte)
    }
    
    return "com.apple.os.update-" + bmhStr
}

class MountPatch {
    let mem: MemoryAccess
    let pe: PostExploitation
    let offsets: Offsets.KernelOffsetsEntry
    
    let mountPath  = "/private/var/mnt"
    
    init(pe: PostExploitation) {
        mem = pe.mem
        offsets = pe.offsets
        self.pe = pe
    }
    
    private func noOTAPresent() -> Bool {
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: "/var/MobileSoftwareUpdate/mnt1", isDirectory: &isDir),
           isDir.boolValue == true {
            do {
                // Check if something is mounted there
                let mnt1Attr = try FileManager.default.attributesOfFileSystem(forPath: "/var/MobileSoftwareUpdate/mnt1")
                let MSUAttr  = try FileManager.default.attributesOfFileSystem(forPath: "/var/MobileSoftwareUpdate")
                
                // If the .systemNumber is the same, no OTA is mounted
                if let mnt1SysNum = mnt1Attr[.systemNumber] as? NSNumber,
                   let MSUSysNum  = MSUAttr [.systemNumber] as? NSNumber {
                    return mnt1SysNum == MSUSysNum
                }
                
                // For safety, return false
                return false
            } catch {
                return true
            }
        }
        
        return true
    }
    
    private static func isRenameRequired() throws -> Bool {
        if access("/.Fugu15Untether", F_OK) == 0 {
            return false
        }
        
        var statBuf = statfs()
        if statfs("/", &statBuf) == 0 {
            return (statBuf.f_flags & UInt32(bitPattern: MNT_SNAPSHOT)) != 0
        }
        
        throw MountError.failedToCheckForRename
    }
    
    private func doRootfsMount(rootVnode: VNode) throws {
        rootVnode.mount?.devvp?.specInfo?.flags = 0
        
        let save = try! pe.giveKernelCreds()
        let retval = "/dev/disk0s1s1".withCString { fspec -> Int32 in
            var mntargs = hfs_mount_args()
            mntargs.fspec = UnsafeMutablePointer(mutating: fspec)
            mntargs.hfs_mask = 1
            gettimeofday(nil, &mntargs.hfs_timezone)
            
            return mount("apfs", mountPath, 0, &mntargs)
        }
        
        let err = errno
        
        try? pe.restoreCreds(saved: save)
        
        if retval != 0 {
            throw MountError.failed(error: err)
        }
    }
    
    private func clearSnapshotFlag(rootVnode: VNode, systemSnapshot: String) throws {
        guard let rootMnt = rootVnode.mount else {
            throw MountError.failedToFindNewMount
        }
        
        for mount in rootMnt {
            if let dev = mount.devvp {
                if dev.name == "disk0s1s1" {
                    guard let vnodelist = mount.vnodelist else {
                        throw MountError.failedToClearSnapshotFlag
                    }
                    
                    for vnode in vnodelist {
                        if vnode.name.hasPrefix("com.apple.os.update-") {
                            if let apfsFlags = vnode.data?.flags,
                               (apfsFlags & SNAPSHOT_FLAG) != 0 {
                                vnode.data?.flags = apfsFlags & ~SNAPSHOT_FLAG
                                return
                            }
                        }
                    }
                    
                    throw MountError.failedToClearSnapshotFlag
                }
            }
        }
        
        throw MountError.failedToFindNewMount
    }
    
    public static func purgeOTA() {
        if let handle = dlopen("/System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/MobileSoftwareUpdate", RTLD_NOW) {
            typealias PurgeFunc = @convention(c) (UnsafeRawPointer?) -> Void
            if let fHndl = dlsym(handle, "MSUPurgeSuspendedUpdate") {
                let MSUPurgeSuspendedUpdate = unsafeBitCast(fHndl, to: PurgeFunc.self)
                
                Logger.print("Purging updates...")
                MSUPurgeSuspendedUpdate(nil)
                Logger.print("Updates purged.")
            } else {
                Logger.print("Failed to find MSUPurgeSuspendedUpdate!")
            }
        } else {
            Logger.print("Failed to open MobileSoftwareUpdate.framework!")
        }
    }
    
    public func remount(launchd: Proc, installCallback: ((_: String) throws -> Void)? = nil) rethrows -> MountResult {
        // First get root vnode
        guard let rootVnode = launchd.textvp?.parent?.parent else {
            return .failed(reason: "Failed to find root vnode!")
        }
        
        var renameRequired = false
        do {
            renameRequired = try Self.isRenameRequired()
        } catch {
            return .failed(reason: "Failed to find out if a rename is required!")
        }
        
        if renameRequired {
            Self.purgeOTA()
            
            if FileManager.default.fileExists(atPath: mountPath) {
                run(prog: "/sbin/umount", args: ["-f", mountPath])
                try? FileManager.default.removeItem(atPath: mountPath)
            }
            
            try? FileManager.default.createDirectory(atPath: mountPath, withIntermediateDirectories: true, attributes: [.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o755])
            defer { rmdir(mountPath) }
            
            if !noOTAPresent() {
                // This should *never* happen
                return .otaAlreadyMounted
            }
            
            guard let systemSnapshot = getSystemSnapshotName() else {
                return .failed(reason: "Failed to find system Snapshot")
            }
            
            do {
                try doRootfsMount(rootVnode: rootVnode)
            } catch _ {
                return .failed(reason: "Mount failed!")
            }
            
            var ok = withFD(file: mountPath) { fd in
                fs_snapshot_revert(fd, systemSnapshot, 0) == 0
            }
            
            guard ok else {
                run(prog: "/sbin/umount", args: ["-f", mountPath])
              
                return .failed(reason: "Snapshot revert failed!")
            }
            
            run(prog: "/sbin/umount", args: ["-f", mountPath])
            
            do {
                try doRootfsMount(rootVnode: rootVnode)
                
                try clearSnapshotFlag(rootVnode: rootVnode, systemSnapshot: systemSnapshot)
            } catch _ {
                run(prog: "/sbin/umount", args: [mountPath])
                return .failed(reason: "Failed to mount without Snapshot Flag")
            }
            
            defer { chdir("/"); run(prog: "/sbin/umount", args: [mountPath]) }
            
            creat(mountPath + "/.Fugu14_Installed", 0o666)
            
            try installCallback?(mountPath)
            
            ok = withFD(file: mountPath) { fd in
                fs_snapshot_rename(fd, systemSnapshot, "orig-fs", 0) == 0
            }
            
            guard ok else {
                return .failed(reason: "Failed to rename snapshot!")
            }
            
            return .rebootRequired
        } else {
            let oldFlags = rootVnode.mount!.flags & ~MNT_RDONLY
            rootVnode.mount?.flags = oldFlags & ~MNT_ROOTFS
            
            run(prog: "/sbin/mount_apfs", args: ["-o", "update", "/dev/disk0s1s1", "/"])
            
            rootVnode.mount?.flags = oldFlags | MNT_NOSUID
            return .ok
        }
    }
    
    public static func restoreRootfs() -> RestoreResult {
        Self.purgeOTA()
        
        var renameRequired = false
        do {
            renameRequired = try Self.isRenameRequired()
        } catch {
            return .failed(reason: "Failed to find out if a rename is required!")
        }
        
        if !renameRequired {
            guard let systemSnapshot = getSystemSnapshotName() else {
                return .failed(reason: "Failed to find system Snapshot")
            }
            
            try? FileManager.default.removeItem(atPath: "/var/cache")
            try? FileManager.default.removeItem(atPath: "/var/lib")
            try? FileManager.default.removeItem(atPath: "/private/var/mnt")
            
            let ok = withFD(file: "/") { fd in
                if fs_snapshot_rename(fd, "orig-fs", systemSnapshot, 0) == 0 {
                    if fs_snapshot_revert(fd, systemSnapshot, 0) == 0 {
                        return true
                    }
                }
                
                return false
            }
            
            guard ok else {
                return .failed(reason: "Snapshot rename/revert failed!")
            }
            
            return .rebootRequired
        } else {
            return .noRestoreRequired
        }
    }
}
