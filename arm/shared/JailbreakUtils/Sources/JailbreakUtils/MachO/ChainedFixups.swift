//
//  ChainedFixups.swift
//  JailbreakUtils
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation

public enum ChainedFixupsError: Error {
    case noChainedFixups
    case noLinkedit
    case unsupportedPointerFormat
}

open class ChainedFixups {
    public typealias ExtendedChainCallback = (_ location: UInt64, _ vAddr: UInt64, _ content: ChainedStartsInSegment.ChainTarget) throws -> Void
    
    public var startsInSegment: [ChainedStartsInSegment?] = []
    public var imports: [String] = []
    public var startForClosure: UInt64
    
    private var machO: MachO
    
    public var highestOrdinal: UInt16? {
        var highest: UInt16 = 0
        
        do {
            try forEachFixup({ (loc, vAddr, target) in
                if case .authBind(ordinal: let ordinal, diversity: _, addrDiv: _, key: _, next: _) = target {
                    if ordinal > highest {
                        highest = ordinal
                    }
                } else if case .bind(ordinal: let ordinal, addend: _, next: _) = target {
                    if ordinal > highest {
                        highest = ordinal
                    }
                }
            })
            
            return highest
        } catch _ {
            return nil
        }
    }
    
    public init(machO: MachO) throws {
        self.machO = machO
        
        guard let chainedInfo: ChainedFixupsLoadCommand = machO.findLoadCommand(ofType: .ChainedFixups) else {
            throw ChainedFixupsError.noChainedFixups
        }
        
        let off = Int(chainedInfo.fixupOffset)
        let end = off + Int(chainedInfo.fixupSize)
        
        guard let chainData = machO.data.trySubdata(in: off..<end) else {
            throw MachOError.ReadError
        }
        
        guard let startsOffset = chainData.tryGetGeneric(type: UInt32.self, offset: 0x4) else {
            throw MachOError.ReadError
        }
        
        startForClosure = UInt64(startsOffset + chainedInfo.fixupOffset)
        
        guard let importsOffset = chainData.tryGetGeneric(type: UInt32.self, offset: 0x8) else {
            throw MachOError.ReadError
        }
        
        guard let symbolsOffset = chainData.tryGetGeneric(type: UInt32.self, offset: 0xC) else {
            throw MachOError.ReadError
        }
        
        guard let importsCount = chainData.tryGetGeneric(type: UInt32.self, offset: 0x10) else {
            throw MachOError.ReadError
        }
        
        guard let importsFormat = chainData.tryGetGeneric(type: UInt32.self, offset: 0x14) else {
            throw MachOError.ReadError
        }
        
        var importsSize = 0
        if importsFormat == 1 {
            importsSize = 4
        } else if importsFormat == 2 {
            importsSize = 8
        } else if importsFormat == 3 {
            importsSize = 16
        } else {
            throw MachOError.BadFormat
        }
        
        guard (importsOffset + importsCount * UInt32(importsSize)) < chainData.count else {
            throw MachOError.BadFormat
        }
        
        guard let segCount = chainData.tryGetGeneric(type: UInt32.self, offset: UInt(startsOffset)) else {
            throw MachOError.ReadError
        }
        
        let start = chainData.advanced(by: Int(startsOffset))
        for i in 0..<UInt(segCount) {
            guard let off = start.tryGetGeneric(type: UInt32.self, offset: 4 + (4 * i)) else {
                throw MachOError.ReadError
            }
            
            if off == 0 {
                startsInSegment.append(nil)
                continue
            }
            
            startsInSegment.append(try ChainedStartsInSegment(machO: machO, data: start.tryAdvance(by: Int(off))))
        }
        
        var curImport = chainData.advanced(by: Int(importsOffset))
        for _ in 0..<UInt(importsCount) {
            var nameOff = 0
            if importsFormat == 3 {
                let tmp = curImport.getGeneric(type: UInt64.self)
                nameOff = Int(tmp >> 32)
            } else {
                let tmp = curImport.getGeneric(type: UInt32.self)
                nameOff = Int(tmp >> 9)
            }
            
            guard (Int(symbolsOffset) + nameOff) < chainData.count else {
                throw MachOError.BadFormat
            }
            
            let name = try chainData.advanced(by: Int(symbolsOffset) + nameOff).toString(encoding: .utf8, nullTerminated: true)
            imports.append(name)
            
            curImport = curImport.advanced(by: importsSize)
        }
    }
    
    public func symbol(forFixup: ChainedFixups.ChainedStartsInSegment.ChainTarget) -> String? {
        if case .authBind(ordinal: let ordinal, diversity: _, addrDiv: _, key: _, next: _) = forFixup {
            if ordinal < imports.count {
                return imports[Int(ordinal)]
            }
        } else if case .bind(ordinal: let ordinal, addend: _, next: _) = forFixup {
            if ordinal < imports.count {
                return imports[Int(ordinal)]
            }
        }
        
        return nil
    }
    
    public func forEachFixup(_ callback: ExtendedChainCallback) throws {
        for i in 0..<startsInSegment.count {
            if startsInSegment[i] != nil {
                guard i < machO.cmds.count,
                      let sectLCmd = machO.cmds[i] as? Segment64LoadCommand else {
                    throw MachOError.BadFormat
                }
                
                try startsInSegment[i]!.forEachFixup({ (loc, target) in
                    try callback(loc, sectLCmd.vmAddr + loc - sectLCmd.fileOffset, target)
                })
            }
        }
    }
    
    public struct ChainedStartsInSegment {
        public typealias ChainCallback = (_ location: UInt64, _ content: ChainTarget) throws -> Void
        
        public var pageSize: UInt16
        public var pointerFormat: UInt16
        public var segOffset: UInt64
        public var maxValidPointer: UInt32 // 32Bit OS only -> unused
        public var pageStarts: [UInt16] = []
        
        private let machO: MachO
        
        public init(machO: MachO, data: Data) throws {
            self.machO = machO
            
            guard let size = data.tryGetGeneric(type: UInt32.self, offset: 0) else {
                throw MachOError.ReadError
            }
            
            guard size >= 0x16 else {
                throw MachOError.BadFormat
            }
            
            guard let newData = data.trySubdata(in: 0..<Int(size)) else {
                throw MachOError.BadFormat
            }
            
            pageSize = newData.getGeneric(type: UInt16.self, offset: 0x4)
            pointerFormat = newData.getGeneric(type: UInt16.self, offset: 0x6)
            segOffset = newData.getGeneric(type: UInt64.self, offset: 0x8)
            maxValidPointer = newData.getGeneric(type: UInt32.self, offset: 0x10)
            
            let pageCount = newData.getGeneric(type: UInt16.self, offset: 0x14)
            
            guard size >= 0x16 + (pageCount * 0x2) else {
                throw MachOError.BadFormat
            }
            
            for i in 0..<UInt(pageCount) {
                pageStarts.append(newData.getGeneric(type: UInt16.self, offset: 0x16 + (i * 0x2)))
            }
        }
        
        public func forEachFixup(_ callback: ChainCallback) throws {
            guard pointerFormat == 1 else {
                throw ChainedFixupsError.unsupportedPointerFormat
            }
            
            guard let start = machO.data.trySubdata(in: Int(segOffset)..<(Int(segOffset) + pageStarts.count * Int(pageSize))) else {
                throw MachOError.BadFormat
            }
            
            for i in 0..<pageStarts.count {
                let off = i * Int(pageSize)
                let pgData = start.subdata(in: off..<(off + Int(pageSize)))
                
                var curOff = UInt(pageStarts[i])
                while curOff < Int(pageSize) {
                    let content = pgData.getGeneric(type: UInt64.self, offset: curOff)
                    let next = (content >> 51) & 0x7FF
                    
                    let loc: UInt64 = segOffset + UInt64(off) + UInt64(curOff)
                    try callback(loc, ChainTarget(rawValue: content))
                    
                    if next == 0 {
                        break
                    }
                    
                    curOff += UInt(next) * 8
                }
            }
        }
        
        public enum ChainTarget: RawRepresentable {
            public enum PACKey: UInt8 {
                case IA = 0
                case IB = 1
                case DA = 2
                case DB = 3
            }
            
            public typealias RawValue = UInt64
            
            public var rawValue: UInt64 {
                switch self {
                    case .authRebase(target: let target, diversity: let diversity, addrDiv: let addrDiv, key: let key, next: let next):
                        var result = UInt64(target)
                        result |= UInt64(diversity) << 32
                        result |= UInt64(addrDiv ? 1 : 0) << 48
                        result |= UInt64(key.rawValue) << 49
                        result |= UInt64(next & 0x7FF) << 51
                        result |= 0x8000000000000000
                        return result
                        
                    case .authBind(ordinal: let ordinal, diversity: let diversity, addrDiv: let addrDiv, key: let key, next: let next):
                        var result = UInt64(ordinal)
                        result |= UInt64(diversity) << 32
                        result |= UInt64(addrDiv ? 1 : 0) << 48
                        result |= UInt64(key.rawValue) << 49
                        result |= UInt64(next & 0x7FF) << 51
                        result |= 0xC000000000000000
                        return result
                        
                    case .rebase(target: let target, high8: let high8, next: let next):
                        var result = target & 0x7FFFFFFFFFF
                        result |= UInt64(high8) << 43
                        result |= UInt64(next & 0x7FF) << 51
                        return result
                        
                    case .bind(ordinal: let ordinal, addend: let addend, next: let next):
                        var result = UInt64(ordinal)
                        result |= UInt64(addend & 0x7FFFF) << 32
                        result |= UInt64(next & 0x7FF) << 51
                        result |= 0x4000000000000000
                        return result
                }
            }
            
            public init(rawValue: UInt64) {
                let type = rawValue >> 62
                switch type {
                    case 0:
                        let target = rawValue & 0x7FFFFFFFFFF
                        let high8 = UInt8((rawValue >> 43) & 0xFF)
                        let next = UInt16((rawValue >> 51) & 0x7FF)
                        self = .rebase(target: target, high8: high8, next: next)
                        
                    case 1:
                        let ordinal = UInt16(rawValue & 0xFFFF)
                        let addend = UInt32((rawValue >> 32) & 0x7FFFF)
                        let next = UInt16((rawValue >> 51) & 0x7FF)
                        self = .bind(ordinal: ordinal, addend: addend, next: next)
                        
                    case 2:
                        let target = UInt32(rawValue & 0xFFFFFFFF)
                        let diversity = UInt16((rawValue >> 32) & 0xFFFF)
                        let addrDiv = ((rawValue >> 48) & 1) == 1
                        let key = PACKey(rawValue: UInt8((rawValue >> 49) & 0x3))!
                        let next = UInt16((rawValue >> 51) & 0x7FF)
                        self = .authRebase(target: target, diversity: diversity, addrDiv: addrDiv, key: key, next: next)
                        
                    case 3:
                        let ordinal = UInt16(rawValue & 0xFFFF)
                        let diversity = UInt16((rawValue >> 32) & 0xFFFF)
                        let addrDiv = ((rawValue >> 48) & 1) == 1
                        let key = PACKey(rawValue: UInt8((rawValue >> 49) & 0x3))!
                        let next = UInt16((rawValue >> 51) & 0x7FF)
                        self = .authBind(ordinal: ordinal, diversity: diversity, addrDiv: addrDiv, key: key, next: next)
                        
                    default:
                        fatalError() // Cannot happen, switch is exhaustive
                }
            }
            
            case authRebase(target: UInt32, diversity: UInt16, addrDiv: Bool, key: PACKey, next: UInt16)
            case authBind(ordinal: UInt16, diversity: UInt16, addrDiv: Bool, key: PACKey, next: UInt16)
            case rebase(target: UInt64, high8: UInt8, next: UInt16)
            case bind(ordinal: UInt16, addend: UInt32, next: UInt16)
        }
    }
}
