# Ret2dlresolve:Solution

The binary is compiled with NX and Partial RELRO
```
pwn checksec chal.bin 
[*] '/root/workspace/vuln/ret2dlresolve/chal/chal.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

and is dynamically linked to GLIBC.
```
ldd chal.bin
    linux-vdso.so.1 (0x00007ffd4a0d8000)
    libc.so.6 => /lib64/libc.so.6 (0x00007ff26e800000)
    /lib64/ld-linux-x86-64.so.2 (0x00007ff26eb17000)\
```

