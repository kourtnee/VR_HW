The binary is compiled with NX, a stack canary, and Full RELRO
```
checksec ./chal.bin
[*] '/root/workspace/vuln/type/chal/chal.bin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Because there was no win function but there was a fail function, and there is a system call. binsh not in binary so we have to write it 
Write to heap because it's a heap challenge. There is a canary and no clear way to leak the canary.

display function checks for guitar and anything other than 31337 is a drum (binja)

in gdb 
borrow guitar
name
test
display instrument
name instrument
AAAAAAAAAAAAAAAA
to overflow

GDB shows 31337 is now something else

binja 
name function
drums 32 are larger than guitars 16
31337 -> address (is guitar)

make drum into guitar 
borrow drum to make space 32 fill with overwrite the one next to 31337 to system 

write binsh to memory

```
flag{D4z3d_and_confus3D_4_s0_l0Ng}
```

Resources:
* Class Slides
* Louie
* Ash
