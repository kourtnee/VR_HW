# Shellcode:Solution

This challenge was a lot harder than the seccomp one, but we were also given a lot of hints for this one as well.

This is the state the registers needed to be in before we called our shellcode:
```
│pwndbg> regs
│ RAX  0x0
│*RBX  0x7ffe57bbff08 —▸ 0x7ffe57bc0599 ◂— '/r
│*RCX  0x7fbe3b23b190 (write+16) ◂— cmp rax, -
│*RDX  0x123412340000 ◂— push 3 /* 0x6a9703ef8
│*RDI  0x7fbe3b317a10 (_IO_stdfile_1_lock) ◂— 
│*RSI  0x1
│*R8   0xffffffff
│ R9   0x0
│*R10  0x7fbe3b152b40 ◂— 0x10001200001a7e
│*R11  0x202
│ R12  0x0
│*R13  0x7ffe57bbff18 —▸ 0x7ffe57bc05d1 ◂— 'SH
│*R14  0x563353a99dd8 (__do_global_dtors_aux_f
│x) ◂— endbr64 
│*R15  0x7fbe3b370020 (_rtld_global
3b3712e0 —▸ 0x563353a96000 ◂— 0x10102464c457f
```

We were also told:
```
arithmetic instructions and stack instructions (push/pop) are your friends
```

The class example was called oddshell, and it came with a "checker", we could use this to check the instructions we were using for this challenge as well.

This challenge needed even bytes as opposed to the odd ones from class, so the code needed to be altered slightly, but it still worked. 

Testing out the various instructions, and looking for good or bad instructions was taking forever. Analyzing the binary made it easier to understand what was actually being checked for.

* Using rabin2 we could see that there was no /bin/sh in the binary.
* syscall was allowed by the binary
* Everything was being "AND"ed by 2 (ex: 0010)
* XOR wasn't an instruction we could use

Obviously we needed to use syscalls to get the flag, but which ones? 

Well since /bin/sh isn't in the binary we have to get it in there, so we can use the read() syscall. For this we need to manipulate rax, rdi, rsi, and rdx.  
read(fd,writeable memory,size)
* rax was already 0                                                                                     -> we need it 0 for read
* since we can't use xor we need to use a combination of push/pop/sub to zero out the rdi register      -> fd - stdin is 0
* we could put rdx into rsi to create the writeable memory                                              -> rdi had writeable memory (convenient)
* rdx was used for the size being read

(Here there was quite the discussion about how much space was needed. Robbie made an argument for 59 due to something with execve, Tyler said it just needed to be bigger than 8. Somehow my code kept the 59 depsite Tyler being right.)

Now we needed to make the execve syscall. 
* rax needed to be 59 for execve                -> this was difficult because we can't pop rax, so we needed to use xchg edi,eax to pass the AND
* the writeable memory needed to be moved from rsi into rdi
* rsi and rdx had to be zeroed out like previously

Putting the two syscalls together was all we needed for the shellcode, then we could send it and read in /bin/sh to get a shell then cat the flag!
```
flag{U_come_CR4sh_in2_m3}
```

Resources:
* Tyler (he came to help with egghunter and stayed to help with shellcode, he hinted toward things that he was helped with, but let us work it out ourselves)
* Robbie and Ash (they spent ages checking for valid instructions while Louie and I fought with egghunter, they saved us the wasted time approaching it from that angle)
* Alex and Ian (they both got phone calls to them, I think it amounted mostly to rubber ducking, but it was a contribution)
* https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
* https://man7.org/linux/man-pages/man2/execve.2.html
* Demo files from class
