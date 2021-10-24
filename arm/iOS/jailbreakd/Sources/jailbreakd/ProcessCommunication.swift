//
//  ProcessCommunication.swift
//  jailbreakd
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import Foundation

class ProcessCommunication {
    let read: FileHandle
    let write: FileHandle
    
    init(read: FileHandle, write: FileHandle) {
        self.read = read
        self.write = write
    }
    
    func receiveArg() -> String? {
        var buf = ""
        while true {
            do {
                let data = try read.read(upToCount: 1)
                if data == nil || data?.count == 0 {
                    return nil
                }
                
                if data.unsafelyUnwrapped[0] == 0 {
                    return buf
                }
                
                buf += String(data: data.unsafelyUnwrapped, encoding: .utf8) ?? ""
            } catch _ {
                return nil
            }
        }
    }
    
    @discardableResult
    func sendArg(_ arg: String) -> Bool {
        do {
            try write.write(contentsOf: arg.data(using: .utf8) ?? Data())
            try write.write(contentsOf: Data(repeating: 0, count: 1))
            return true
        } catch _ {
            return false
        }
    }
}
