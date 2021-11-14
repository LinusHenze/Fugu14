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

    return lines.join('\n');
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
