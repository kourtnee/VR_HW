# Ret2libc:Solution

The binary is compiled with NX and Partial RELRO
```
 pwn checksec chal.bin                                                      
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)              
[*] '/root/workspace/vuln/ret2libc/chal/chal.bin'                              
    Arch:     amd64-64-little                                                  
    RELRO:    Partial RELRO                                                    
    Stack:    No canary found                                                  
    NX:       NX enabled                                                       
    PIE:      No PIE (0x400000) 
```
    
and is dynamically linked to GLIBC.
```
ldd chal.bin
    linux-vdso.so.1 (0x00007fff24bd2000)
    libc.so.6 => /lib64/libc.so.6 (0x00007f4778600000)
    /lib64/ld-linux-x86-64.so.2 (0x00007f477896e000)
```
