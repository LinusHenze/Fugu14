//
//  ARM64Inst.swift
//  ClosurePwn
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation

open class ARM64Inst {
    static func ldrImmArgs(ofInstruction inst: UInt32, is64: inout Bool, dst: inout UInt8, src: inout UInt8, srcOff: inout UInt16) -> Bool {
        if (inst & 0xBFC00000) != 0xB9400000 {
            return false
        }
        
        is64 = ((inst >> 30) & 1) == 1
        dst = UInt8(clamping: inst & 0x1F)
        src = UInt8(clamping: (inst >> 5) & 0x1F)
        srcOff = UInt16(clamping: ((inst >> 10) & 0xFFF) << 3)
        
        return true
    }
    
    static func strImmArgs(ofInstruction inst: UInt32, is64: inout Bool, src: inout UInt8, dst: inout UInt8, dstOff: inout UInt16) -> Bool {
        if (inst & 0xBFC00000) != 0xB9000000 {
            return false
        }
        
        is64 = ((inst >> 30) & 1) == 1
        src = UInt8(clamping: inst & 0x1F)
        dst = UInt8(clamping: (inst >> 5) & 0x1F)
        dstOff = UInt16(clamping: ((inst >> 10) & 0xFFF) << 3)
        
        return true
    }
    
    static func emulateAdrp(instruction: UInt32, pc: UInt64) -> UInt64? {
        // Check that this is an adrp instruction
        if ((instruction & 0x9F000000) != 0x90000000) {
            return nil
        }
        
        // Calculate imm from hi and lo
        var imm_hi_lo = (instruction & 0xFFFFE0) >> 3
        imm_hi_lo |= (instruction & 0x60000000) >> 29
        if (instruction & 0x800000) != 0 {
            // Sign extend
            imm_hi_lo |= 0xFFE00000
        }
        
        // Build real imm
        let imm = (Int64(imm_hi_lo) << 12);
        
        // Emulate
        return (pc & ~0xFFF) &+ UInt64(bitPattern: imm)
    }
    
    static func emulateAdrpLdr(adrp: UInt32, ldr: UInt32, pc: UInt64) -> UInt64? {
        guard let adrp_target = emulateAdrp(instruction: adrp, pc: pc) else {
            return nil
        }
        
        if (adrp & 0x1F) != ((ldr >> 5) & 0x1F) {
            return nil
        }
        
        if (ldr & 0xFFC00000) != 0xF9400000 {
            return nil
        }
        
        let imm12 = ((ldr >> 10) & 0xFFF) << 3
        
        // Emulate
        return adrp_target &+ UInt64(imm12);
    }
}
