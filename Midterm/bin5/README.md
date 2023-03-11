# bin5:Solution(nope)

The binary is compiled with NX, a stack canary, and partial RELRO
```
checksec chal.bin 
[*] '/root/workspace/vuln/midterm/ctfd/bin5/chal.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

This binary has a read function and a few gets calls that could be exploitable. I ran out of time for further analysis.
