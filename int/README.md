# INT:Solution

The binary is compiled with NX, PIE, a stack canary, and no RELRO.
```
checksec chal.bin 
[*] '/root/workspace/vuln/int/chal/chal.bin'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

