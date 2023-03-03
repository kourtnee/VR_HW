# Seccomp:Solution

Going into this challenge we knew it was going to use assembly/shellcode. We were also given the hint of shellcraft.eggfinder.

Looking at the binary in binja, we could see that the main function called a function called load_flag.

load_flag calls read to read the flag.txt file:
```
read(fd: rax_8, buf: rax_3, nbytes: 0x64)
```

Then the main function returns to the exec_shellcode function. This is where we can enter our exploit into the read function it provides:
```
read(fd: 0, buf: rax_1, nbytes: 4096)
```

The exec_shellcode function also calls the secure_binary function that defines the seccomp rules for the binary:
```
   1 @ 00001302  seccomp_rule_add(rax, 0x7fff0000, 0x15, 0)
   2 @ 00001322  seccomp_rule_add(rax, 0x7fff0000, 1, 0)
```

The two syscalls are:  
0x15 -> 21 -> sys_access  
1 -> sys_write 

So the first thing we had to do was find the flag, which could be done with:  
```
shellcraft.amd64.linux.egghunter(b'flag')
```

The documentation says that this should load the value found into RDI, however while viewing this in GDB it appeared to go intop RSI, which caused a lot of confusion.

Viewing it in there, however did provide us with the location of the flag: 0x600054.

If the assembly for the eggfinder is printed out, it's seen to be making use of the sys_access syscall.

The next part we need is to write the flag out.

We can use shellcraft for this part as well:
```
shellcraft.amd64.linux.write(1, 'rdi', 50)
```
(this was assuming the documentation was correct and that the flag was in RDI)

From here we could convert these with asm() and send them to the binary to get the flag. Except that didn't work, and reviewing the assembly created from the shellcraft functions looked correct.

Louie and I spent over an hour stepping through everything in GDB and couldn't figure out why it was behaving the way it was. 

Eventually Tyler told us something avout the egghunter function that solved the problem. Starting at zero and searching for the flag left something out of the generated assembly that we needed.

Using the location of the flag we could see in the registers in GDB, we could get the right assembly:
```
shellcraft.amd64.linux.egghunter(b'flag', 0x600054)
```

When that gets sent in, we get the flag!



## OR

Alternatively since we know the location of the flag, we can write the assembly for the write() syscall ourselves.
```
mov rax, 0x1          (write)
mov rdi, 0x1          (fd -> stdout)
mov rsi, 0x60054      (buf)
mov rdx, 40           (count)
syscall
```

It really turned out that doing it by hand in this case would have been faster than using the built in tools, but it was worht learning the functionality for future use.

Running the exploit gave a flag!
```
flag{HeLL0_Darkn3ss_MY_0Lld_fri3nD}
```

Resources:
* Louie (we sat together and tried to get the egghunter thing to work for hours)
* Tyler (he saved us much pain)
* Robbie, Alex (rubbed it in that it was easier to do it by hand until we did it that way too)
* https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
* https://man7.org/linux/man-pages/man2/access.2.html
* https://docs.pwntools.com/en/stable/shellcraft/amd64.html
