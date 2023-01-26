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
    
