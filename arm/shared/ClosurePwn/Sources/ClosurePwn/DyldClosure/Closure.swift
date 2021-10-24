//
//  Closure.swift
//  ClosurePwn
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation

public func deserializeClosureItem(data: Data) throws -> ClosureItem {
    guard data.count >= 4 else {
        throw ClosureError.LengthError(data: data, expected: 4)
    }
    
    let typeSize = data.getGeneric(type: UInt32.self)
    let type = UInt8(typeSize & 0xFF)
    let size = typeSize >> 8
    
    guard data.count >= (size + 4) else {
        throw ClosureError.LengthError(data: data, expected: size + 4)
    }
    
    switch type {
        case 1:
            return try LaunchClosure(fromData: data)
            
        case 2:
            return try ImageArray(fromData: data)
            
        case 3:
            return try Image(fromData: data)
            
        // 4
        // 5
        // 6
            
        case 7:
            return try ImageFlags(fromData: data)
            
        case 8:
            return try PathAndHash(fromData: data)
            
        case 9:
            return try FileInfo(fromData: data)
            
        case 10:
            return try CDHashEntry(fromData: data)
            
        case 11:
            return try ImageUUID(fromData: data)
            
        case 12:
            return try MappingInfo(fromData: data)
            
        case 13:
            return try DiskSegments(fromData: data)
            
        // 14
            
        case 15:
            return try Dependents(fromData: data)
            
        // 16
        // 17
        
        case 18:
            return try CodeSignatureLocation(fromData: data)
        
        // 19
        // 20
        
        case 21:
            return try BindFixups(fromData: data)
            
        // 22
        // 23
        // 24
        
        case 25:
            return try InitBefores(fromData: data)
            
        // 26
        
        case 27:
            return try ChainedFixupsEntry(fromData: data)
        
        // 28
        
        case 29:
            return try ChainedFixupsStart(fromData: data)
        
        case 30:
            return try ObjCFixups(fromData: data)
            
        // 31
        
        case 32:
            return try ClosureFlags(fromData: data)
            
        case 33:
            return try DyldUUID(fromData: data)
            
        case 34:
            return try MissingFiles(fromData: data)
            
        // 35
        
        case 36:
            return try TopImage(fromData: data)
            
        case 37:
            return try LibDyldEntry(fromData: data)
            
        case 38:
            return try LibSystemNumber(fromData: data)
            
        // 39
        
        case 40:
            return try MainEntry(fromData: data)
            
        case 41:
            return try StartEntry(fromData: data)
            
        case 42:
            return try CacheOverrides(fromData: data)
            
        default:
            return try GenericClosureItem(fromData: data)
    }
}

public enum ClosureError: Error {
    case LengthError(data: Data, expected: UInt32)
    case TypeError(expected: UInt8, got: UInt8)
}

public protocol ClosureItem {
    var type: UInt8 { get }
    
    init()
    init(fromData data: Data) throws
    func emit() -> Data
}

public extension ClosureItem {
    var length: UInt32 { UInt32(emit().count) }
    
    static func _parse(data: Data, requiredType: UInt8? = nil) throws -> (type: UInt8, data: Data) {
        guard data.count >= 4 else {
            throw ClosureError.LengthError(data: data, expected: 4)
        }
        
        let typeSize = data.getGeneric(type: UInt32.self)
        let type = UInt8(typeSize & 0xFF)
        let size = typeSize >> 8
        
        guard data.count >= (size + 4) else {
            throw ClosureError.LengthError(data: data, expected: size + 4)
        }
        
        guard requiredType == nil || requiredType! == type else {
            throw ClosureError.TypeError(expected: requiredType!, got: type)
        }
        
        return (type: type, data: data.subdata(in: 4..<Data.Index(4+size)))
    }
    
    func _emit(data: Data) -> Data {
        let sizeType = (UInt32(data.count) << 8) | UInt32(type)
        
        var res = Data(fromObject: sizeType)
        res.append(data)
        
        return res
    }
}

public protocol ClosureItemContainer: AnyObject, ClosureItem {
    var children: [ClosureItem] { get set }
}

public extension ClosureItemContainer {
    func findChild(byType type: UInt8) -> ClosureItem? {
        for c in children {
            if c.type == type {
                return c
            }
        }
        
        return nil
    }
    
    func getOrCreateChild<T: ClosureItem>(type: UInt8) -> T {
        if let found = findChild(byType: type) as? T {
            return found
        }
        
        let new = T()
        children.append(new)
        
        return new
    }
    
    func _getterImpl<T: ClosureItem>(type: T.Type, typeNumber: UInt8) -> T? {
        return findChild(byType: typeNumber) as? T
    }
    
    func _setterImpl<T: ClosureItem>(typeNumber: UInt8, newValue: T?) {
        children.removeAll(where: { $0.type == typeNumber })
        if newValue != nil {
            children.append(newValue!)
        }
    }
}

open class GenericClosureItem: ClosureItem {
    public var type: UInt8 = 0
    public var data: Data = Data()
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data)
        
        self.type = res.type
        self.data = res.data
    }
    
    public func emit() -> Data {
        return _emit(data: data)
    }
}

open class LaunchClosure: ClosureItemContainer {
    public var type: UInt8 { 1 }
    public var children: [ClosureItem] = []
    
    public var topImageNumber: UInt32? {
        get {
            _getterImpl(type: TopImage.self, typeNumber: 36)?.imageNumber
        }
        
        set {
            if newValue != nil {
                let top: TopImage = getOrCreateChild(type: 36)
                top.imageNumber = newValue!
            } else {
                children.removeAll { $0.type == 36 }
            }
        }
    }
    public var topImage: Image? {
        get {
            if let array = imageArray {
                if let topImNum = topImageNumber {
                    let res = array.images.filter({ $0.imageNumber == topImNum })
                    if res.count == 1 {
                        return res[0]
                    }
                }
            }
            
            return nil
        }
        
        set {
            if let array = imageArray {
                if let topImNum = topImageNumber {
                    array.images.removeAll(where: { $0.imageNumber == topImNum })
                    if newValue != nil {
                        array.images.append(newValue!)
                    }
                }
            }
        }
    }
    public var imageArray: ImageArray? {
        get {
            _getterImpl(type: ImageArray.self, typeNumber: 2)
        }
        
        set {
            _setterImpl(typeNumber: 2, newValue: newValue)
        }
    }
    public var flags: ClosureFlags? {
        get {
            _getterImpl(type: ClosureFlags.self, typeNumber: 32)
        }
        
        set {
            _setterImpl(typeNumber: 32, newValue: newValue)
        }
    }
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        
        while data.count > 0 {
            let deserialized = try deserializeClosureItem(data: data)
            children.append(deserialized)
            
            if deserialized.length >= data.count {
                break
            }
            
            data = data.advanced(by: Int(deserialized.length))
        }
        
        assert(self.emit() == inData, "Emit returned wrong data!")
    }
    
    public func emit() -> Data {
        var data = Data()
        
        for c in children {
            data.append(c.emit())
        }
        
        return _emit(data: data)
    }
    
    public func findChild(byType type: UInt8) -> ClosureItem? {
        for c in children {
            if c.type == type {
                return c
            }
        }
        
        return nil
    }
    
    public func findImage(byNumber: UInt32) -> Image? {
        guard let imArray = findChild(byType: 2) as? ImageArray else {
            return nil
        }
        
        for i in imArray.images {
            if let imNum = i.imageNumber,
               imNum == byNumber {
                return i
            }
        }
        
        return nil
    }
}

open class ImageArray: ClosureItem {
    public var type: UInt8 { 2 }
    public var firstImageNumber: UInt32 = 0
    public var hasRoots: Bool = false
    public var images: [Image] = []
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data, requiredType: self.type)
        
        guard res.data.count >= 8 else {
            throw ClosureError.LengthError(data: res.data, expected: 8)
        }
        
        firstImageNumber = res.data.getGeneric(type: UInt32.self)
        let rootCount = res.data.getGeneric(type: UInt32.self, offset: 4)
        let count = rootCount & 0x7FFFFFFF
        hasRoots = (rootCount >> 31) == 1
        
        if count >= 1 {
            guard res.data.count >= 12 else {
                throw ClosureError.LengthError(data: res.data, expected: 12)
            }
            
            let offsets = res.data.advanced(by: 8)
            for i in 0..<UInt(count) {
                guard res.data.count >= 12 + (i*4) else {
                    throw ClosureError.LengthError(data: res.data, expected: 12 + UInt32(i*4))
                }
                
                let offset = offsets.getGeneric(type: UInt32.self, offset: i * 4)
                let imageData = res.data.advanced(by: Int(offset))
                
                let image = try deserializeClosureItem(data: imageData)
                images.append(image as! Image)
            }
        }
    }
    
    public func emit() -> Data {
        var offsets = Data()
        var data = Data()
        
        // First the offsets, then the data
        // Length of the offsets is 8 + images.count * 4
        let startOffset = 8 + (images.count * 4)
        
        for im in images {
            offsets.appendGeneric(value: UInt32(startOffset + data.count))
            data.append(im.emit())
        }
        
        // Generate infos
        // These come before the offsets
        var infos = Data(fromObject: firstImageNumber)
        infos.appendGeneric(value: UInt32(images.count) | (hasRoots ? 0x80000000 : 0))
        
        // Now emit
        return _emit(data: infos + offsets + data)
    }
}

open class Image: ClosureItemContainer {
    public var type: UInt8 { 3 }
    public var children: [ClosureItem] = []
    
    private var _machOData: Data? = nil
    public var machOData: Data? {
        get {
            if _machOData != nil {
                return _machOData!
            }
            
            if let pathHash = findChild(byType: 8) as? PathAndHash {
                _machOData = try? Data(contentsOf: URL(fileURLWithPath: pathHash.path))
            }
            
            return _machOData
        }
        
        set {
            _machOData = newValue
        }
    }
    
    public var flags: ImageFlags? {
        get {
            _getterImpl(type: ImageFlags.self, typeNumber: 7)
        }
        
        set {
            _setterImpl(typeNumber: 7, newValue: newValue)
        }
    }
    public var imageNumber: UInt32? {
        get {
            if let num = flags?.imageNum {
                return UInt32(num)
            }
            
            return nil
        }
        
        set {
            if let val = newValue {
                var f = flags
                if f == nil {
                    f = ImageFlags()
                    children.insert(f!, at: 0)
                }
                
                f!.imageNum = UInt16(val)
            }
        }
    }
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        
        while data.count > 0 {
            let deserialized = try deserializeClosureItem(data: data)
            children.append(deserialized)
            
            if deserialized.length >= data.count {
                break
            }
            
            data = data.advanced(by: Int(deserialized.length))
        }
    }
    
    public func emit() -> Data {
        var data = Data()
        
        for c in children {
            data.append(c.emit())
        }
        
        return _emit(data: data)
    }
}

open class ImageFlags: ClosureItem {
    public var type: UInt8 { 7 }
    public var rawFlags: UInt64 = 0
    
    public var imageNum: UInt16 {
        get { rawFlags.get(withMask: 0xFFFF) }
        set { rawFlags.set(withMask: 0xFFFF, value: newValue) }
    }
    public var maxLoadCount: UInt16 {
        get { rawFlags.get(withMask: 0xFFF, andShift: 16) }
        set { rawFlags.set(withMask: 0xFFF, andShift: 16, value: newValue) }
    }
    public var isInvalid: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 28) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 28, value: newValue ? 1 : 0) }
    }
    public var has16KBPages: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 29) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 29, value: newValue ? 1 : 0) }
    }
    public var is64: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 30) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 30, value: newValue ? 1 : 0) }
    }
    public var hasObjC: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 31) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 31, value: newValue ? 1 : 0) }
    }
    public var mayHavePlusLoads: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 32) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 32, value: newValue ? 1 : 0) }
    }
    public var isEncrypted: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 33) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 33, value: newValue ? 1 : 0) }
    }
    public var hasWeakDefs: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 34) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 34, value: newValue ? 1 : 0) }
    }
    public var neverUnload: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 35) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 35, value: newValue ? 1 : 0) }
    }
    public var cwdSameAsThis: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 36) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 36, value: newValue ? 1 : 0) }
    }
    public var isPlatformBinary: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 37) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 37, value: newValue ? 1 : 0) }
    }
    public var isBundle: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 38) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 38, value: newValue ? 1 : 0) }
    }
    public var isDylib: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 39) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 39, value: newValue ? 1 : 0) }
    }
    public var isExecutable: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 40) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 40, value: newValue ? 1 : 0) }
    }
    public var overridableDylib: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 41) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 41, value: newValue ? 1 : 0) }
    }
    public var inDyldCache: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 42) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 42, value: newValue ? 1 : 0) }
    }
    public var hasTerminators: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 43) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 43, value: newValue ? 1 : 0) }
    }
    public var hasReadOnlyData: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 44) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 44, value: newValue ? 1 : 0) }
    }
    public var hasChainedFixups: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 45) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 45, value: newValue ? 1 : 0) }
    }
    public var hasPrecomputedObjC: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 46) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 46, value: newValue ? 1 : 0) }
    }
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data, requiredType: self.type)
        
        guard res.data.count >= 8 else {
            throw ClosureError.LengthError(data: res.data, expected: 8)
        }
        
        rawFlags = res.data.getGeneric(type: UInt64.self)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: rawFlags)
        
        return _emit(data: data)
    }
}

open class PathAndHash: ClosureItem {
    public var type: UInt8 { 8 }
    public private(set) var hash: UInt32 = 0
    
    private var _path: String = ""
    public var path: String {
        get { _path }
        set { _path = newValue; hashPath() }
    }
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data, requiredType: self.type)
        
        guard res.data.count >= 5 else {
            throw ClosureError.LengthError(data: res.data, expected: 8)
        }
        
        let foundHash = res.data.getGeneric(type: UInt32.self)
        _path = String(data: res.data.advanced(by: 4), encoding: .utf8)!
        while _path.last != nil && _path.last! == "\0" {
            _path.removeLast()
        }
        
        hashPath()
        
        assert(hash == foundHash, "Bad closure or hash calculation is broken")
        assert(emit().advanced(by: 4) == res.data)
    }
    
    public func emit() -> Data {
        var data = Data(fromObject: hash)
        data.append(_path.data(using: .utf8)!)
        while data.last == nil || data.last! != 0 || (data.count % 4) != 0 {
            data.append(Data(repeating: 0, count: 1))
        }
        
        return _emit(data: data)
    }
    
    private func hashPath() {
        var h: UInt32 = 0
        for c in _path.utf8CString {
            if c == 0 {
                break
            }
            
            h = (h &* 5) &+ UInt32(UInt8(bitPattern: c))
        }
        
        hash = h
    }
}

open class FileInfo: ClosureItem {
    public var type: UInt8 { 9 }
    public var inode: UInt64 = 0
    public var modTime: UInt64 = 0
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data, requiredType: self.type)
        
        guard res.data.count >= 16 else {
            throw ClosureError.LengthError(data: res.data, expected: 16)
        }
        
        inode = res.data.getGeneric(type: UInt64.self)
        modTime = res.data.getGeneric(type: UInt64.self, offset: 8)
    }
    
    public func emit() -> Data {
        var data = Data(fromObject: inode)
        data.appendGeneric(value: modTime)
        
        return _emit(data: data)
    }
}

open class CDHashEntry: ClosureItem {
    public var type: UInt8 { 10 }
    public var cdHash: Data = Data()
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data, requiredType: self.type)
        
        guard res.data.count == 20 else {
            throw ClosureError.LengthError(data: res.data, expected: 20)
        }
        
        cdHash = res.data
    }
    
    public func emit() -> Data {
        assert(cdHash.count == 20, "CDHash must always be 20 Bytes long!")
        
        return _emit(data: cdHash)
    }
}

open class ImageUUID: ClosureItem {
    public var type: UInt8 { 11 }
    public var uuid: uuid_t = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data, requiredType: self.type)
        
        guard res.data.count >= 16 else {
            throw ClosureError.LengthError(data: res.data, expected: 16)
        }
        
        uuid = res.data.getGeneric(type: uuid_t.self)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: uuid)
        
        return _emit(data: data)
    }
}

open class MappingInfo: ClosureItem {
    public var type: UInt8 { 12 }
    public var totalVMPages: UInt32 = 0
    public var sliceOffsetIn4K: UInt32 = 0
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data, requiredType: self.type)
        
        guard res.data.count >= 8 else {
            throw ClosureError.LengthError(data: res.data, expected: 20)
        }
        
        totalVMPages = res.data.getGeneric(type: UInt32.self)
        sliceOffsetIn4K = res.data.getGeneric(type: UInt32.self, offset: 4)
    }
    
    public func emit() -> Data {
        var data = Data(fromObject: totalVMPages)
        data.appendGeneric(value: sliceOffsetIn4K)
        
        return _emit(data: data)
    }
}

open class DiskSegments: ClosureItem {
    open class DiskSegment: CustomReflectable {
        public var rawValue: UInt64 = 0
        
        public var filePageCount: UInt32 {
            get { rawValue.get(withMask: 0x3FFFFFFF) }
            set { rawValue.set(withMask: 0x3FFFFFFF, value: newValue) }
        }
        public var vmPageCount: UInt32 {
            get { rawValue.get(withMask: 0x3FFFFFFF, andShift: 30) }
            set { rawValue.set(withMask: 0x3FFFFFFF, andShift: 30, value: newValue) }
        }
        public var permissions: UInt8 {
            get { rawValue.get(withMask: 0x7, andShift: 60) }
            set { rawValue.set(withMask: 0x7, andShift: 60, value: newValue) }
        }
        public var paddingNotSegment: Bool {
            get { rawValue.get(withMask: 0x1, andShift: 63) == 1 }
            set { rawValue.set(withMask: 0x1, andShift: 63, value: newValue ? 1 : 0) }
        }
        
        public var permissionString: String {
            var res = ""
            if (permissions & 0x1) != 0 {
                res += "r"
            } else {
                res += "-"
            }
            
            if (permissions & 0x2) != 0 {
                res += "w"
            } else {
                res += "-"
            }
            
            if (permissions & 0x4) != 0 {
                res += "x"
            } else {
                res += "-"
            }
            
            return res
        }
        
        public var customMirror: Mirror {
            Mirror(DiskSegment.self, children: [
                "rawValue": rawValue,
                "filePageCount": filePageCount,
                "vmPageCount": vmPageCount,
                "permissions": permissionString,
                "paddingNotSegment": paddingNotSegment
            ], displayStyle: .class)
        }
        
        init() {}
        
        init(withRawValue: UInt64) {
            rawValue = withRawValue
        }
    }
    
    public var type: UInt8 { 13 }
    public var segments: [DiskSegment] = []
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        
        while data.count >= 8 {
            let seg = DiskSegment(withRawValue: data.getGeneric(type: UInt64.self))
            segments.append(seg)
            
            if data.count == 8 {
                break
            }
            
            data = data.advanced(by: 8)
        }
        
        assert(res.data.count == 0 || self.emit().advanced(by: 4) == res.data, "Emit returned wrong data!")
    }
    
    public func emit() -> Data {
        var data = Data()
        
        for s in segments {
            data.append(Data(fromObject: s.rawValue))
        }
        
        return _emit(data: data)
    }
}

open class Dependents: ClosureItem {
    open class LinkedImage: CustomReflectable {
        public enum LinkKind: UInt32 {
            case regular = 0
            case weak = 1
            case upward = 2
            case reExport = 3
        }
        
        public var rawValue: UInt32 = 0
        
        public var imageNumber: UInt32 {
            get { rawValue.get(withMask: 0x3FFFFFFF) }
            set { rawValue.set(withMask: 0x3FFFFFFF, value: newValue) }
        }
        public var linkKind: LinkKind {
            get { LinkKind(rawValue: rawValue.get(withMask: 0x3, andShift: 30))! }
            set { rawValue.set(withMask: 0x3, andShift: 30, value: newValue.rawValue) }
        }
        
        public var customMirror: Mirror {
            Mirror(LinkedImage.self, children: [
                "rawValue": rawValue,
                "imageNumber": imageNumber,
                "linkKind": linkKind
            ], displayStyle: .class, ancestorRepresentation: .suppressed)
        }
        
        init() {}
        
        init(withRawValue: UInt32) {
            rawValue = withRawValue
        }
        
        init(withImageNumber: UInt32, andLinkKind: LinkKind) {
            imageNumber = withImageNumber
            linkKind = andLinkKind
        }
    }
    
    public var type: UInt8 { 15 }
    public var images: [LinkedImage] = []
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        
        while data.count >= 4 {
            let seg = LinkedImage(withRawValue: data.getGeneric(type: UInt32.self))
            images.append(seg)
            
            if data.count == 4 {
                break
            }
            
            data = data.advanced(by: 4)
        }
        
        assert(self.emit().tryAdvance(by: 4) == res.data, "Emit returned wrong data!")
    }
    
    public func emit() -> Data {
        var data = Data()
        
        for i in images {
            data.append(Data(fromObject: i.rawValue))
        }
        
        return _emit(data: data)
    }
}

open class CodeSignatureLocation: ClosureItem {
    public var type: UInt8 { 18 }
    public var fileOffset: UInt32 = 0
    public var fileSize: UInt32 = 0
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        
        while data.count >= 8 {
            fileOffset = data.getGeneric(type: UInt32.self)
            fileSize = data.getGeneric(type: UInt32.self, offset: 4)
            
            if data.count == 8 {
                break
            }
            
            data = data.advanced(by: 8)
        }
        
        assert(self.emit().advanced(by: 4) == res.data, "Emit returned wrong data!")
    }
    
    public func emit() -> Data {
        var data = Data(fromObject: fileOffset)
        data.appendGeneric(value: fileSize)
        
        return _emit(data: data)
    }
}

public enum ResolvedSymbolTarget: RawRepresentable {
    case rebase
    case sharedCache(offset: UInt64)
    case image(number: UInt32, offset: UInt64)
    case absolute(address: UInt64)
    
    public var rawValue: UInt64 {
        switch self {
            case .rebase:
                return 0
            
            case .sharedCache(offset: let offset):
                return (offset << 2) | 1
                
            case .image(number: let number, offset: let offset):
                return ((UInt64(number) & 0xFFFFF) << 2) | ((offset & 0xFFFFFFFFFF) << 24) | 2
                
            case .absolute(address: let address):
                return (address << 2) | 3
        }
    }
    
    public init(rawValue: UInt64) {
        switch rawValue & 0x3 {
            case 0:
                self = .rebase
            
            case 1:
                self = .sharedCache(offset: rawValue >> 2)
                
            case 2:
                self = .image(number: UInt32((rawValue >> 2) & 0xFFFFF), offset: (rawValue & 0xFFFFFFFFFF000000) >> 24)
                
            case 3:
                self = .absolute(address: rawValue >> 2)
                
            default: // unreachable
                fatalError()
        }
    }
}

open class BindFixups: ClosureItem {
    open class BindPattern {
        public var target: ResolvedSymbolTarget = .rebase
        public var rawAdditionalData: UInt64 = 0
        
        public var startVmOffset: UInt64 {
            get { rawAdditionalData.get(withMask: 0xFFFFFFFFFF) }
            set { rawAdditionalData.set(withMask: 0xFFFFFFFFFF, value: newValue) }
        }
        public var skipCount: UInt8 {
            get { rawAdditionalData.get(withMask: 0xFF, andShift: 40) }
            set { rawAdditionalData.set(withMask: 0xFF, andShift: 40, value: newValue) }
        }
        public var repeatCount: UInt16 {
            get { rawAdditionalData.get(withMask: 0xFFFF, andShift: 48) }
            set { rawAdditionalData.set(withMask: 0xFFFF, andShift: 48, value: newValue) }
        }
        
        public init() {}
        
        public init(withTarget: ResolvedSymbolTarget, andAdditionalData: UInt64) {
            target = withTarget
            rawAdditionalData = andAdditionalData
        }
        
        public init(withTarget: ResolvedSymbolTarget, andVMOffset: UInt64) {
            target = withTarget
            startVmOffset = andVMOffset
            repeatCount = 1
        }
    }
    
    public var type: UInt8 { 21 }
    public var patterns: [BindPattern] = []
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        
        while data.count >= 16 {
            let seg = BindPattern(withTarget: .init(rawValue: data.getGeneric(type: UInt64.self)), andAdditionalData: data.getGeneric(type: UInt64.self, offset: 8))
            patterns.append(seg)
            
            assert(seg.target.rawValue == data.getGeneric(type: UInt64.self))
            assert(seg.rawAdditionalData == data.getGeneric(type: UInt64.self, offset: 8))
            
            if data.count == 16 {
                break
            }
            
            data = data.advanced(by: 16)
        }
        
        assert(self.emit().advanced(by: 4) == res.data, "Emit returned wrong data!")
    }
    
    public func emit() -> Data {
        var data = Data()
        
        for p in patterns {
            data.appendGeneric(value: p.target.rawValue as UInt64)
            data.appendGeneric(value: p.rawAdditionalData as UInt64)
        }
        
        return _emit(data: data)
    }
}

open class InitBefores: ClosureItem {
    public var type: UInt8 { 25 }
    public var images: [UInt32] = []
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        
        while data.count >= 4 {
            images.append(data.getGeneric(type: UInt32.self))
            
            if data.count == 4 {
                break
            }
            
            data = data.advanced(by: 4)
        }
        
        assert(res.data.count == 0 || self.emit().advanced(by: 4) == res.data, "Emit returned wrong data!")
    }
    
    public func emit() -> Data {
        var data = Data()
        
        for i in images {
            data.appendGeneric(value: i)
        }
        
        return _emit(data: data)
    }
}

open class ChainedFixupsEntry: ClosureItem {
    public var type: UInt8 { 27 }
    public var targets: [ResolvedSymbolTarget] = []
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        
        while data.count >= 8 {
            let seg = ResolvedSymbolTarget.init(rawValue: data.getGeneric(type: UInt64.self))
            targets.append(seg)
            
            assert(seg.rawValue == data.getGeneric(type: UInt64.self))
            
            if data.count == 8 {
                break
            }
            
            data = data.advanced(by: 8)
        }
        
        assert(self.emit().advanced(by: 4) == res.data, "Emit returned wrong data!")
    }
    
    public func emit() -> Data {
        var data = Data()
        
        for t in targets {
            data.appendGeneric(value: t.rawValue)
        }
        
        return _emit(data: data)
    }
}

open class ChainedFixupsStart: ClosureItem {
    public var type: UInt8 { 29 }
    public var start: UInt64 = 0
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        guard res.data.count >= 8 else {
            throw ClosureError.LengthError(data: res.data, expected: 8)
        }
        
        start = res.data.getGeneric(type: UInt64.self)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: start)
        
        return _emit(data: data)
    }
}

open class ObjCFixups: ClosureItem {
    open class ProtocolISAFixup {
        public var rawValue: UInt64 = 0
        
        public var startOffset: UInt64 {
            get {
                rawValue.get(withMask: 0xFFFFFFFFFF)
            }
            
            set {
                rawValue.set(withMask: 0xFFFFFFFFFF, value: newValue)
            }
        }
        public var skipCount: UInt8 {
            get {
                rawValue.get(withMask: 0xFF, andShift: 40)
            }
            
            set {
                rawValue.set(withMask: 0xFF, andShift: 40, value: newValue)
            }
        }
        public var repeatCount: UInt16 {
            get {
                rawValue.get(withMask: 0xFFFF, andShift: 48)
            }
            
            set {
                rawValue.set(withMask: 0xFFFF, andShift: 48, value: newValue)
            }
        }
        
        public init() {}
        
        public init(fromData inData: Data) {
            rawValue = inData.getGeneric(type: UInt64.self)
        }
        
        public func emit() -> Data {
            return Data(fromObject: rawValue)
        }
    }
    
    open class SelectorReferenceFixup {
        public var rawValue: UInt32 = 0
        
        public var index: UInt32 {
            get {
                rawValue.get(withMask: 0xFFFFFF)
            }
            
            set {
                rawValue.set(withMask: 0xFFFFFF, value: newValue)
            }
        }
        public var next: UInt8 {
            get {
                rawValue.get(withMask: 0x7F, andShift: 24)
            }
            
            set {
                rawValue.set(withMask: 0x7F, andShift: 24, value: newValue)
            }
        }
        public var sharedCache: Bool {
            get {
                rawValue.get(withMask: 1, andShift: 31) == 1
            }
            
            set {
                rawValue.set(withMask: 1, andShift: 31, value: newValue ? 1 : 0)
            }
        }
        
        public init() {}
        
        public init(fromData inData: Data) {
            rawValue = inData.getGeneric(type: UInt32.self)
        }
        
        public func emit() -> Data {
            return Data(fromObject: rawValue)
        }
    }
    
    open class StableSwiftFixup {
        public var theData = Data()
        
        public init() {}
        
        public init(fromData inData: Data) {
            theData = inData.subdata(in: 0..<8)
        }
        
        public func emit() -> Data {
            return theData
        }
    }
    
    open class MethodListFixup {
        public var theData = Data()
        
        public init() {}
        
        public init(fromData inData: Data) {
            theData = inData.subdata(in: 0..<8)
        }
        
        public func emit() -> Data {
            return theData
        }
    }
    
    public var type: UInt8 { 30 }
    public var protocolClassTarget: ResolvedSymbolTarget = .rebase
    public var imageInfoVMOffset: UInt64 = 0
    public var protocolFixups: [ProtocolISAFixup] = []
    public var selectorFixups: [SelectorReferenceFixup] = []
    public var stableSwiftFixups: [StableSwiftFixup] = []
    public var methodListFixups: [MethodListFixup] = []
    
    public var forceOldVersion = false
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        guard res.data.count >= 24 else {
            throw ClosureError.LengthError(data: res.data, expected: 24)
        }
        
        protocolClassTarget = ResolvedSymbolTarget.init(rawValue: res.data.getGeneric(type: UInt64.self))
        imageInfoVMOffset = res.data.getGeneric(type: UInt64.self, offset: 8)
        
        let protoFixCount = res.data.getGeneric(type: UInt32.self, offset: 16)
        let selFixCount = res.data.getGeneric(type: UInt32.self, offset: 20)
        
        guard res.data.count >= 24 + (protoFixCount * 8) + (selFixCount * 4) else {
            throw ClosureError.LengthError(data: res.data, expected: 24 + (protoFixCount * 8) + (selFixCount * 4))
        }
        
        for i in 0..<Int(protoFixCount) {
            let proto = ProtocolISAFixup(fromData: res.data.advanced(by: 24 + (i * 8)))
            protocolFixups.append(proto)
        }
        
        for i in 0..<Int(selFixCount) {
            let proto = SelectorReferenceFixup(fromData: res.data.advanced(by: 24 + (Int(protoFixCount) * 8) + (i * 4)))
            selectorFixups.append(proto)
        }
        
        if res.data.count > 24 + (protoFixCount * 8) + (selFixCount * 4) {
            let nextPart = res.data.advanced(by: 24 + (Int(protoFixCount) * 8) + (Int(selFixCount) * 4))
            let swiftFixCount = nextPart.getGeneric(type: UInt32.self)
            let methodListFixCount = nextPart.getGeneric(type: UInt32.self, offset: 4)
            
            guard nextPart.count >= 8 + (swiftFixCount * 8) + (methodListFixCount * 8) else {
                throw ClosureError.LengthError(data: nextPart, expected: 8 + (swiftFixCount * 8) + (methodListFixCount * 8))
            }
            
            for i in 0..<Int(swiftFixCount) {
                let proto = StableSwiftFixup(fromData: nextPart.advanced(by: 8 + (i * 8)))
                stableSwiftFixups.append(proto)
            }
            
            for i in 0..<Int(methodListFixCount) {
                let proto = MethodListFixup(fromData: nextPart.advanced(by: 8 + (Int(swiftFixCount) * 8) + (i * 8)))
                methodListFixups.append(proto)
            }
        } else {
            forceOldVersion = true
        }
        
        assert(emit().advanced(by: 4) == res.data)
    }
    
    public func emit() -> Data {
        var result = Data()
        result.appendGeneric(value: protocolClassTarget.rawValue)
        result.appendGeneric(value: imageInfoVMOffset)
        result.appendGeneric(value: UInt32(protocolFixups.count))
        result.appendGeneric(value: UInt32(selectorFixups.count))
        
        for p in protocolFixups {
            result.append(p.emit())
        }
        
        for s in selectorFixups {
            result.append(s.emit())
        }
        
        if !forceOldVersion || stableSwiftFixups.count > 0 || methodListFixups.count > 0 {
            result.appendGeneric(value: UInt32(stableSwiftFixups.count))
            result.appendGeneric(value: UInt32(methodListFixups.count))
            
            for s in stableSwiftFixups {
                result.append(s.emit())
            }
            
            for m in methodListFixups {
                result.append(m.emit())
            }
        }
        
        return _emit(data: result)
    }
    
    public func iterateSelectors(_ callback: (_ offset: UInt32, _ fixup: SelectorReferenceFixup) -> Void) {
        var i = 0
        
        while i < selectorFixups.count {
            var off = selectorFixups[i].rawValue
            i += 1
            
            while i < selectorFixups.count {
                let entry = selectorFixups[i]
                callback(off, entry)
                
                if entry.next == 0 {
                    break
                }
                
                off += 4 * UInt32(entry.next)
                i += 1
            }
            
            i += 1
        }
    }
    
    public func deleteSelector(withOffset wanted: UInt32) -> Bool {
        var i = 0
        
        while i < selectorFixups.count {
            let chainIndex = i
            var off = selectorFixups[i].rawValue
            i += 1
            
            while i < selectorFixups.count {
                let entry = selectorFixups[i]
                
                if off == wanted {
                    // Ok, remove this
                    // First check if we're the only entry in the chain
                    if i == (chainIndex + 1) && entry.next == 0 {
                        // Just delete whole chain
                        selectorFixups.remove(at: chainIndex)
                        selectorFixups.remove(at: chainIndex)
                        return true
                    }
                    
                    // Then handle the case that we're the first entry in the chain
                    if i == (chainIndex + 1) {
                        // Adjust chain start
                        selectorFixups[chainIndex].rawValue += 4 * UInt32(entry.next)
                        selectorFixups.remove(at: i)
                        return true
                    }
                    
                    // Handle the case that we're the last entry
                    if entry.next == 0 {
                        selectorFixups[i - 1].next = 0
                        selectorFixups.remove(at: i)
                        return true
                    }
                    
                    // Finally: In the middle of the chain
                    selectorFixups[i - 1].next += entry.next
                    selectorFixups.remove(at: i)
                    return true
                }
                
                if entry.next == 0 {
                    break
                }
                
                off += 4 * UInt32(entry.next)
                i += 1
            }
            
            i += 1
        }
        
        return false
    }
}

open class ClosureFlags: ClosureItem {
    public var type: UInt8 { 32 }
    public var rawFlags: UInt32 = 0
    
    public var usedAtPaths: Bool {
        get { rawFlags.get(withMask: 0x1) == 1 }
        set { rawFlags.set(withMask: 0x1, value: newValue ? 1 : 0) }
    }
    public var usedFallbackPaths: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 1) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 1, value: newValue ? 1 : 0) }
    }
    public var initImageCount: UInt16 {
        get { rawFlags.get(withMask: 0xFFFF, andShift: 2) }
        set { rawFlags.set(withMask: 0xFFFF, andShift: 2, value: newValue) }
    }
    public var hasInsertedLibraries: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 18) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 18, value: newValue ? 1 : 0) }
    }
    public var hasProgVars: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 19) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 19, value: newValue ? 1 : 0) }
    }
    public var usedInterposing: Bool {
        get { rawFlags.get(withMask: 0x1, andShift: 20) == 1 }
        set { rawFlags.set(withMask: 0x1, andShift: 20, value: newValue ? 1 : 0) }
    }
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data, requiredType: self.type)
        
        guard res.data.count >= 4 else {
            throw ClosureError.LengthError(data: res.data, expected: 4)
        }
        
        rawFlags = res.data.getGeneric(type: UInt32.self)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: rawFlags)
        
        return _emit(data: data)
    }
}

open class DyldUUID: ClosureItem {
    public var type: UInt8 { 33 }
    public var uuid: uuid_t = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    public required init() {}
    
    public required init(fromData data: Data) throws {
        let res = try Self._parse(data: data, requiredType: self.type)
        
        guard res.data.count >= 16 else {
            throw ClosureError.LengthError(data: res.data, expected: 16)
        }
        
        uuid = res.data.getGeneric(type: uuid_t.self)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: uuid)
        
        return _emit(data: data)
    }
}

open class MissingFiles: ClosureItem {
    public var type: UInt8 { 34 }
    public var files: [String] = []
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        var curStr = ""
        while data.count > 0 {
            let char = data.getGeneric(type: CChar.self)
            if char == 0 {
                files.append(curStr)
                curStr = ""
            } else {
                curStr += String(format: "%c", char)
            }
            
            data = data.advanced(by: 1)
        }
        
        if curStr != "" {
            files.append(curStr)
        }
    }
    
    public func emit() -> Data {
        var data = Data()
        for s in files {
            var tmp = s.data(using: .utf8)!
            if tmp.count == 0 || tmp.last! != 0 {
                tmp.append(Data(repeating: 0, count: 1))
            }
            
            data.append(tmp)
        }
        
        return _emit(data: data)
    }
}

open class TopImage: ClosureItem {
    public var type: UInt8 { 36 }
    public var imageNumber: UInt32 = 0
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        guard res.data.count >= 4 else {
            throw ClosureError.LengthError(data: res.data, expected: 4)
        }
        
        imageNumber = res.data.getGeneric(type: UInt32.self)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: imageNumber)
        
        return _emit(data: data)
    }
}

open class LibDyldEntry: ClosureItem {
    public var type: UInt8 { 37 }
    public var target: ResolvedSymbolTarget = .rebase
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        guard res.data.count >= 4 else {
            throw ClosureError.LengthError(data: res.data, expected: 4)
        }
        
        let raw = res.data.getGeneric(type: UInt64.self)
        
        target = .init(rawValue: raw)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: target.rawValue)
        
        return _emit(data: data)
    }
}

open class LibSystemNumber: ClosureItem {
    public var type: UInt8 { 38 }
    public var imageNumber: UInt32 = 0
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        guard res.data.count >= 4 else {
            throw ClosureError.LengthError(data: res.data, expected: 4)
        }
        
        imageNumber = res.data.getGeneric(type: UInt32.self)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: imageNumber)
        
        return _emit(data: data)
    }
}

open class MainEntry: ClosureItem {
    public var type: UInt8 { 40 }
    public var target: ResolvedSymbolTarget = .rebase
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        guard res.data.count >= 4 else {
            throw ClosureError.LengthError(data: res.data, expected: 4)
        }
        
        let raw = res.data.getGeneric(type: UInt64.self)
        
        target = .init(rawValue: raw)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: target.rawValue)
        
        return _emit(data: data)
    }
}

open class StartEntry: ClosureItem {
    public var type: UInt8 { 41 }
    public var target: ResolvedSymbolTarget = .rebase
    
    public required init() {}
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        guard res.data.count >= 4 else {
            throw ClosureError.LengthError(data: res.data, expected: 4)
        }
        
        let raw = res.data.getGeneric(type: UInt64.self)
        
        target = .init(rawValue: raw)
    }
    
    public func emit() -> Data {
        let data = Data(fromObject: target.rawValue)
        
        return _emit(data: data)
    }
}

open class CacheOverrides: ClosureItem {
    open class PatchEntry {
        public var cacheImageNum: UInt32 = 0 // Image where the exported symbol is located
        public var exportOffset: UInt32  = 0 // Offset in cache of the exported symbol
        public var target: ResolvedSymbolTarget = .rebase
        
        init() {}
        
        init(withTarget: ResolvedSymbolTarget, imageNumber: UInt32, offset: UInt32) {
            target = withTarget
            cacheImageNum = imageNumber
            exportOffset = offset
        }
    }
    
    public var type: UInt8 { 42 }
    public var patches: [PatchEntry] = []
    
    public required init() {}
    
    public init(withPatches: [PatchEntry]) {
        patches = withPatches
    }
    
    public required init(fromData inData: Data) throws {
        let res = try Self._parse(data: inData, requiredType: self.type)
        
        var data = res.data
        
        while data.count >= 16 {
            let pt = PatchEntry(withTarget: .init(rawValue: data.getGeneric(type: UInt64.self, offset: 8)), imageNumber: data.getGeneric(type: UInt32.self), offset: data.getGeneric(type: UInt32.self, offset: 4))
            patches.append(pt)
            
            if data.count == 16 {
                break
            }
            
            data = data.advanced(by: 16)
        }
        
        assert(self.emit().advanced(by: 4) == res.data, "Emit returned wrong data!")
    }
    
    public func emit() -> Data {
        var data = Data()
        
        for p in patches {
            data.appendGeneric(value: p.cacheImageNum as UInt32)
            data.appendGeneric(value: p.exportOffset as UInt32)
            data.appendGeneric(value: p.target.rawValue as UInt64)
        }
        
        return _emit(data: data)
    }
}
