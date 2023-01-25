# Ret2csu:Solution


The binary is compiled with NX and Partial RELRO 
```
pwn checksec ./chal.bin
[*] '/root/workspace/vuln/ret2csu/chal/chal.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  './'
```

and is dynamically linked to GLIBC.
```
ldd ./chal.bin
	libhelper.so => ./libhelper.so (0x0000004001a00000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x0000004001c56000)
	/lib64/ld-linux-x86-64.so.2 (0x0000004000000000)
```


