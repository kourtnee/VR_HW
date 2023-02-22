# Oob:Solution

The binary is compiled with NX, a stack canary, and PIE
```
checksec chal.bin 
[*] '/root/workspace/vuln/oob/chal/chal.bin'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

When we look at the binary in GDB, we can break at main, run it, then look at the got values. 
```
GOT protection: No RELRO | GOT functions: 7
 
[0x555555557500] __stack_chk_fail@GLIBC_2.4 -> 0x555555555036 (__stack_chk_fail@plt+6) ◂— push 0 /* 'h' */
[0x555555557508] setbuf@GLIBC_2.2.5 -> 0x7ffff7c88060 (setbuf) ◂— endbr64 
[0x555555557510] system@GLIBC_2.2.5 -> 0x555555555056 (system@plt+6) ◂— push 2
[0x555555557518] printf@GLIBC_2.2.5 -> 0x555555555066 (printf@plt+6) ◂— push 3
[0x555555557520] read@GLIBC_2.2.5 -> 0x555555555076 (read@plt+6) ◂— push 4
[0x555555557528] __isoc99_scanf@GLIBC_2.7 -> 0x555555555086 (__isoc99_scanf@plt+6) ◂— push 5
[0x555555557530] exit@GLIBC_2.2.5 -> 0x555555555096 (exit@plt+6) ◂— push 6
```

Looking at the binary in binja, we could see that the menu function makes a call to the exit function. Since exit hadn't been initialized yet we could write to it.
```
000035e8  extern void exit(int32_t status) __noreturn
```

Since this was an out of bounds problem, I started trying negative numbers. When I tried -3 it gave me a memory address. Using GDB I was able to check each negative numbers output from memory. Eventually I found that -6 produced the call to exit.
```
pwndbg> x/s 0x555555555096
0x555555555096 <exit@plt+6>:    "h\006"
```

So next I had to figure out how to get the flag. Looking through the functions in binja we can see that the function 'admin' has a system call to /bin/sh. So we need to write the address of that function into exit.
```
admin:
   0 @ 0000120b  void* fsbase
   1 @ 0000120b  int64_t rax = (fsbase + 0x28)
   2 @ 00001224  system(line: "/bin/sh")
   3 @ 0000122e  int64_t rax_2 = rax -(fsbase + 0x28)
   4 @ 00001237  if (rax == *(fsbase + 0x28))
```

Then when the program comes back to the menu we just have to choose the song that will call the exit function, since the exit function now contained the admin function address. From there we use interactive part of process to cat the flag and get the flag!

```
flag{Th1s_T3rr1ble_S1l3nc3_st0ps_m3}
```

Resources:
* Class Slides
* Louie
