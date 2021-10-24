//
//  MachOError.swift
//  JailbreakUtils
//
//  Created by Linus Henze on 2020-04-08.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

import Foundation

public enum MachOError: Error {
    case ReadError
    case InvalidMagic
    case FatNotMachO
    case NestedFAT // FAT inside FAT
    case BadFormat
}
