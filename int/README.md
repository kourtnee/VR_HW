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

```
flag{Until_I_c0uldnt_s33_th3_dang3r_0R_h34r_th3_r1s1nG_t1d3}
```

Resources:
* Class Slides 
* Louie
