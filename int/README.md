# Int:Solution

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

For this binary we can see in binja that there is a vuln function and a win function. The win function contains a system call to /bin/sh, so we just need to get the win function to run.
```
win:
   0 @ 000015e9  void* fsbase
   1 @ 000015e9  int64_t rax = (fsbase + 0x28)
   2 @ 00001602  system(line: "/bin/sh")
   3 @ 0000160c  int64_t rax_2 = rax -(fsbase + 0x28)
   4 @ 00001615  if (rax == *(fsbase + 0x28))
```

When the program is run, vuln leaks a random value, we can use this to find the offset. The input is stored as an int which means we have 32 bytes.
```
vuln:
   0 @ 00001691  void* fsbase
   1 @ 00001691  int64_t rax = *(fsbase + 0x28)
   2 @ 000016a5  int32_t rax_2 = rand_value()
```

We can subtract the random number from two times the value of the overflow and be more than 0 and pass the check, and it will equal 2 so that it will pass the copmparison to the number used when choosing to borrow a drum. 
```
00001849  if (rax_17 == rax_2) -> 00001850  win()
```

Then we can send in the overflow that will give us the win function, where we can cat the flag!
```
flag{Until_I_c0uldnt_s33_th3_dang3r_0R_h34r_th3_r1s1nG_t1d3}
```

Resources:
* Class Slides 
* Louie
