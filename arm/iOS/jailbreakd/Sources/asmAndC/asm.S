//
//  asm.S
//  jailbreakd - asmAndC
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

.text
.align 4

.globl _doMagic
_doMagic:
    ldr x0, =0x4949494949494949
    str x0, [x23]
    str x0, [x23,#0x8]

    str x22, [x21,x24]
    mov x0, x23
    add x0, x0, 0xC
    mov x1, 0x6
    mov x2, x23
    mov x3, x23
    mov x4, 0
    mov x5, 0
    ldr s1, =0x42424242
    ldr s2, =0x43434343
    ldr s3, =0x44444444
    ldr s4, =0x45454545
    mov x16, #274
    svc #0x80
doMagicLoop:
    b doMagicLoop

.globl _userReturn
_userReturn:
    ldr x23, =0x12345678
    b _userReturn
