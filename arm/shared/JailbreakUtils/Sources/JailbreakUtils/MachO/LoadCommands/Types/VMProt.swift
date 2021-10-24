//
//  VMProt.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-10.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

public struct VMProt: OptionSet {
    public let rawValue: UInt32
    
    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
    
    static let Read    = VMProt(rawValue: 0x01)
    static let Write   = VMProt(rawValue: 0x02)
    static let Execute = VMProt(rawValue: 0x04)
}
