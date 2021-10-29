//
//  ContentView.swift
//  Fugu14
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

import SwiftUI
import ClosurePwn

let altStoreBuild = false

struct ContentView: View {
    let isPreview: Bool
    let jailbroken: Bool
    @State var labelText   = ""
    @State var showButton  = true
    @State var showAlert   = false
    @State var showJBAlert = true
    
    var body: some View {
        if jailbroken {
            Text("Please reboot into the non-jailbroken state to use the Fugu14 App")
                .padding()
                .alert(isPresented: self.$showJBAlert) {
                    Alert(title: Text("Reboot required"), message: Text("Please reboot into the non-jailbroken state to use the Fugu14 App"), dismissButton: .default(Text("OK")))
                }
        } else if showButton {
            ZStack {
                Button("Setup Fugu14", action: {
                    showButton = false
                    DispatchQueue(label: "Fugu14Setup").async {
                        doSetup()
                    }
                })
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(10)
                    .foregroundColor(Color.white)
                
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
                        .alert(isPresented: self.$showAlert) {
                            Alert(title: Text("Setup done"), message: Text(altStoreBuild ? "Please open AltStore to continue installing the untether." : "Please update me now."), dismissButton: .default(Text("OK")))
                        }
                }
            }
        }
    }
    
    init(isPreview: Bool = false) {
        self.isPreview = isPreview
        jailbroken = (getenv("DYLD_INSERT_LIBRARIES") != nil)
    }
    
    func print(_ text: String) {
        labelText += text + "\n"
    }
    
    func doSetup() {
        print("Setting up Fugu14")
        
        // Get rid of old temp closures
        let cacheDir = String(cString: getenv("HOME")) + "/Library/Caches/com.apple.dyld"
        if let closures = try? FileManager.default.contentsOfDirectory(atPath: cacheDir) {
            for c in closures {
                if c != "." && c != ".." && !c.hasSuffix(".closure") {
                    try? FileManager.default.removeItem(at: URL(fileURLWithPath: c, relativeTo: URL(fileURLWithPath: cacheDir)))
                }
            }
        }
        
        let home = String(cString: getenv("HOME"))
        let dyldDir = home + "/Library/Caches/com.apple.dyld"
        print("DYLD dir path: \(dyldDir)")
        
        // Closure Paths
        let spotlightClosurePath     = dyldDir + "/Fugu14App.closure"
        let keybagClosurePath        = dyldDir + "/stage2.closure"
        let containerMngrClosurePath = dyldDir + "/stage3.closure"
        let psClosurePath            = dyldDir + "/stage4.closure"
        
        // Unset immutable
        chflags(spotlightClosurePath, 0)
        chflags(keybagClosurePath, 0)
        chflags(containerMngrClosurePath, 0)
        chflags(psClosurePath, 0)
        
        // Remove old closures
        unlink(spotlightClosurePath)
        unlink(keybagClosurePath)
        unlink(containerMngrClosurePath)
        unlink(psClosurePath)
        
        do {
            print("Generating closure for Spotlight...")
            let spotlightCl = try SpotlightClosure().getClosure()
            print("Spotlight closure generated.")
            
            print("Generating closure for keybagd...")
            let keybagCl = try KeybagClosure().getClosure()
            print("keybagd closure generated.")
            
            print("Generating closure for containermanagerd...")
            let containermngrCl = try ContainermngrClosure().getClosure()
            print("containermanagerd closure generated.")
            
            print("Generating closure for ps...")
            let psCl = try PSClosure().getClosure()
            print("ps closure generated.")
            
            // Write new closures
            print("Writing closures")
            try spotlightCl.emit().write(to: URL(fileURLWithPath: spotlightClosurePath))
            try keybagCl.emit().write(to: URL(fileURLWithPath: keybagClosurePath))
            try containermngrCl.emit().write(to: URL(fileURLWithPath: containerMngrClosurePath))
            try psCl.emit().write(to: URL(fileURLWithPath: psClosurePath))
            
            // Set UF_IMMUTABLE
            print("Ensuring closures are immutable")
            chflags(spotlightClosurePath, __uint32_t(UF_IMMUTABLE))
            chflags(keybagClosurePath, __uint32_t(UF_IMMUTABLE))
            chflags(containerMngrClosurePath, __uint32_t(UF_IMMUTABLE))
            chflags(psClosurePath, __uint32_t(UF_IMMUTABLE))
            
            print("Done. Please update me now.")
            print("Note: After closing this App, it won't start again until you update it")
            
            showAlert.toggle()
        } catch let e {
            print("Setup failed! Error: \(e)")
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView(isPreview: true)
    }
}
