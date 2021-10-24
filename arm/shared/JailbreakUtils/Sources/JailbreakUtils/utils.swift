//
//  utils.swift
//  Fugu/JailbreakUtils
//
//  Created by Linus Henze on 2019-10-12.
//  Copyright © 2019-2021 Linus Henze. All rights reserved.
//

import Foundation

func require(_ condition: Bool, function: String = #function, file: String = #file, line: Int = #line) {
    if !condition {
        fail("Assertion failure!", function: function, file: file, line: line)
    }
}

func fail(_ message: String = "<No description provided>", function: String = #function, file: String = #file, line: Int = #line) -> Never {
    let debugInfos = "\n\nDebugging information:\nFunction: \(function)\nFile: \(file)\nLine: \(line)"
    
    print("\nFatal Error: " + message + debugInfos)
    exit(-SIGILL)
}

public class StringDecodingError: Error, CustomStringConvertible {
    private let _value: Data
    public var value: Data { _value }
    
    private let _encoding: String.Encoding
    public var encoding: String.Encoding { _encoding }
    
    public var description: String {
        return "Data \(value) cannot be decoded as \(encoding)"
    }
    
    public init(_ value: Data, encoding: String.Encoding) {
        _value = value
        _encoding = encoding
    }
}

// Utils for working with Data objects
public extension Data {
    /**
     * Get the raw data of an object
     *
     * - warning: This function is UNSAFE as it could leak pointers. Use with caution!
     *
     * - parameter fromObject: The object whose raw data you would like to get
     */
    init<Type: Any>(fromObject: Type) {
        var value = fromObject
        let valueSize = MemoryLayout.size(ofValue: value)
        
        self = withUnsafePointer(to: &value) { ptr in
            Data(bytes: UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self), count: valueSize)
        }
    }
    
    /**
     * Convert an object to raw data and append
     *
     * - warning: This function is UNSAFE as it could leak pointers. Use with caution!
     *
     * - parameter value: The value to convert and append
     */
    mutating func appendGeneric<Type: Any>(value: Type) {
        self.append(Data(fromObject: value))
    }
    
    /**
     * Convert raw data directly into an object
     *
     * - warning: This function is UNSAFE as it could be used to deserialize pointers. Use with caution!
     *
     * - parameter type: The type to convert the raw data into
     */
    func getGeneric<Object: Any>(type: Object.Type, offset: UInt = 0) -> Object {
        guard (Int(offset) + MemoryLayout<Object>.size) <= self.count else {
            fatalError("Tried to read out of bounds!")
        }
        
        return withUnsafeBytes { ptr in
            ptr.baseAddress!.advanced(by: Int(offset)).assumingMemoryBound(to: Object.self).pointee
        }
    }
    
    /**
     * Convert raw data directly into an object, if possible
     *
     * - warning: This function is UNSAFE as it could be used to deserialize pointers. Use with caution!
     *
     * - parameter type: The type to convert the raw data into
     */
    func tryGetGeneric<Object: Any>(type: Object.Type, offset: UInt = 0) -> Object? {
        guard (Int(offset) + MemoryLayout<Object>.size) <= self.count else {
            return nil
        }
        
        return withUnsafeBytes { ptr in
            ptr.baseAddress!.advanced(by: Int(offset)).assumingMemoryBound(to: Object.self).pointee
        }
    }
    
    /**
     * Bug workaround: advance crashes when passing self.count
     */
    func tryAdvance(by: Int) -> Data {
        if by >= self.count {
            return Data()
        }
        
        return self.advanced(by: by)
    }
    
    func trySubdata(in: Range<Index>) -> Data? {
        guard `in`.lowerBound >= 0 && `in`.upperBound <= self.count else {
            return nil
        }
        
        return subdata(in: `in`)
    }
    
    func toString(encoding: String.Encoding = .utf8, nullTerminated: Bool = false) throws -> String {
        if nullTerminated, let index = self.firstIndex(of: 0) {
            let new = self[..<index]
            return try new.toString(encoding: encoding)
        }
        
        guard let str = String(data: self, encoding: encoding) else {
            throw StringDecodingError(self, encoding: encoding)
        }
        
        return str
    }
}

public extension String {
    func decodeHex() -> Data? {
        if (count % 2) != 0 {
            return nil
        }
        
        var result = Data()
        
        var index = startIndex
        while index != endIndex {
            let x = self[index]
            index = self.index(after: index)
            
            let y = self[index]
            index = self.index(after: index)
            
            guard let byte = UInt8(String(x)+String(y), radix: 16) else {
                return nil
            }
            
            result.appendGeneric(value: byte)
        }
        
        return result
    }
}

public extension BinaryInteger {
    func get<Res: BinaryInteger>(withMask mask: Self, andShift shift: Self = 0) -> Res {
        return Res(truncatingIfNeeded: (self >> shift) & mask)
    }
    
    mutating func set<X: BinaryInteger>(withMask mask: Self, andShift shift: Self = 0, value: X) {
        let val = Self.init(truncatingIfNeeded: value) << Self.init(truncatingIfNeeded: shift)
        let msk = mask << shift
        self = (self & ~msk) | (val & msk)
    }
}

public extension Array {
    mutating func prepend(_ newElement: Element) {
        insert(newElement, at: 0)
    }
}

public extension KeyValuePairs where Key: Equatable {
    subscript(key: Key) -> Value? {
        for v in self {
            if v.key == key {
                return v.value
            }
        }
        
        return nil
    }
}

public extension KeyValuePairs where Value: Equatable {
    func firstKeyOf(value: Value) -> Key? {
        for v in self {
            if v.value == value {
                return v.key
            }
        }
        
        return nil
    }
}

public func stripPtr(_ ptr: OpaquePointer) -> OpaquePointer {
    return OpaquePointer(bitPattern: UInt(stripPtr(UInt64(UInt(bitPattern: ptr)))))!
}

public func stripPtr(_ ptr: UInt64) -> UInt64 {
    if ((ptr >> 55) & 1) == 1 {
        // Kernel pointer
        return ptr | 0xFFFFFF8000000000
    }
    
    return ptr & 0x7FFFFFFFFF
}
