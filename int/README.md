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

explain math of 2^32 and 
recv random num from server 
2 times 2^32 - random num second number is 2 
