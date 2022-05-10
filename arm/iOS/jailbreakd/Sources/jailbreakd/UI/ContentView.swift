//
//  ContentView.swift
//  jailbreakd
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import SwiftUI
import UIKit
import externalCStuff

let installButtonStr = altStoreBuild ? "Install Untether" : "Jailbreak + Untether"

struct ContentView: View {
    let alreadyInstalled: Bool
    @State var labelText = ""
    @State var showButton = true
    
    var body: some View {
        if showButton {
            ZStack {
                VStack {
                    Button(alreadyInstalled ? "Restore RootFS" : installButtonStr, action: {
                        showButton = false
                        DispatchQueue(label: "Fugu14").async {
                            if alreadyInstalled {
                                _ = launchServer(uninstall: true)
                            } else {
                                if let comm = launchServer() {
                                    doInstall(comm: comm)
                                }
                            }
                        }
                    })
                        .padding()
                        .background(Color.blue)
                        .cornerRadius(10)
                        .foregroundColor(Color.white)
                    
                    if alreadyInstalled {
                        Button("Update Untether", action: {
                            showButton = false
                            DispatchQueue(label: "Fugu14").async {
                                if let comm = launchServer() {
                                    doUpdate(comm: comm)
                                }
                            }
                        })
                            .padding()
                            .background(Color.blue)
                            .cornerRadius(10)
                            .foregroundColor(Color.white)
                    }
                }
                
                VStack {
                    Spacer()
                    Spacer()
                    Spacer()
                    Button("Show credits", action: {
                        UIApplication.shared.open(URL(string: "https://github.com/LinusHenze/Fugu14/blob/master/credits.txt")!)
                    })
                        .padding()
                    Button("Show license", action: {
                        UIApplication.shared.open(URL(string: "https://github.com/LinusHenze/Fugu14/blob/master/LICENSE")!)
                    })
                    Spacer()
                }
            }
        } else {
            ScrollViewReader { reader in
                ScrollView{
                    Text(labelText)
                        .padding()
                        .frame(minWidth: 0,
                               maxWidth: .infinity,
                               minHeight: 0,
                               maxHeight: .infinity,
                               alignment: .topLeading)
                        .id("label")
                        .onChange(of: labelText, perform: { value in
                            reader.scrollTo("label", anchor: .bottom)
                        })
                }
            }
        }
    }
    
    init() {
        alreadyInstalled = access("/.Fugu14Untether", F_OK) == 0
    }
    
    private func print(_ text: String, ender: String = "\n") {
        DispatchQueue.main.async {
            labelText += text + ender
        }
    }
    
    func launchServer(uninstall: Bool = false) -> ProcessCommunication? {
        print("Launching kernel exploit server... ", ender: "")
        
        // Create pipes to use for communication
        // We use control and log pipes
        let controlToChild = Pipe()
        let controlFromChild = Pipe()
        let logFromChild = Pipe()
        
        // We're entitled to do that ;)
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        posix_spawnattr_set_persona_np(&attr, 99, 1)
        posix_spawnattr_set_persona_uid_np(&attr, 0)
        posix_spawnattr_set_persona_gid_np(&attr, 0)
        
        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)
        //posix_spawn_file_actions_addinherit_np(&fileActions, controlToChild.fileHandleForReading.fileDescriptor)
        posix_spawn_file_actions_addclose(&fileActions, controlToChild.fileHandleForWriting.fileDescriptor)
        posix_spawn_file_actions_addclose(&fileActions, controlFromChild.fileHandleForReading.fileDescriptor)
        //posix_spawn_file_actions_addinherit_np(&fileActions, controlFromChild.fileHandleForWriting.fileDescriptor)
        posix_spawn_file_actions_addclose(&fileActions, logFromChild.fileHandleForReading.fileDescriptor)
        //posix_spawn_file_actions_addinherit_np(&fileActions, logFromChild.fileHandleForWriting.fileDescriptor)
        
        var pid: pid_t = 0
        var argv: [UnsafeMutablePointer<CChar>?] = [CommandLine.unsafeArgv[0], uninstall ? strdup("uninstall") : strdup("server"), strdup("\(controlToChild.fileHandleForReading.fileDescriptor)"), strdup("\(controlFromChild.fileHandleForWriting.fileDescriptor)"), strdup("\(logFromChild.fileHandleForWriting.fileDescriptor)"), nil]
        let result = posix_spawn(&pid, CommandLine.arguments[0], &fileActions, &attr, &argv, environ)
        let err = errno
        guard result == 0 else {
            print("Failed")
            print("Error: \(result) Errno: \(err)")
            return nil
        }
        
        print("Launched")
        
        print("Sending ping to kernel exploit server")
        
        try? controlToChild.fileHandleForReading.close()
        try? controlFromChild.fileHandleForWriting.close()
        try? logFromChild.fileHandleForWriting.close()
        
        DispatchQueue(label: "Fugu14-Logging").async {
            while true {
                do {
                    let data = try logFromChild.fileHandleForReading.read(upToCount: 1)
                    if data == nil || data?.count == 0 {
                        return
                    }
                    
                    print(try data!.toString(), ender: "")
                } catch _ {
                    return
                }
            }
        }
        
        let comm = ProcessCommunication(read: controlFromChild.fileHandleForReading, write: controlToChild.fileHandleForWriting)
        comm.sendArg("ping")
        
        guard comm.receiveArg() == "pong" else {
            print("Didn't receive pong from kernel exploit server!")
            return nil
        }
        
        print("Received pong from kernel exploit server")
        return comm
    }
    
    func doInstall(comm: ProcessCommunication) {
        print("Requesting install")
        comm.sendArg("install")
    }
    
    func doUninstall(comm: ProcessCommunication) {
        print("Requesting uninstall")
        comm.sendArg("uninstall")
    }
    
    func doUpdate(comm: ProcessCommunication) {
        print("Requesting update")
        comm.sendArg("update")
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
