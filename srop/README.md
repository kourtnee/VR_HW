# SROP:Solution

The binary is compiled with NX and Partial RELRO
```
pwn checksec chal.bin                                                               
[*] '/root/workspace/vuln/srop/chal/chal.bin'                                  
    Arch:     amd64-64-little                                                  
    RELRO:    Partial RELRO                                                    
    Stack:    No canary found                                                 
    NX:       NX enabled                                                       
    PIE:      No PIE (0x400000)
```

