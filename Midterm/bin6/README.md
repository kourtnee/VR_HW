# bin6:Solution(nope)

The binary is compiled with NX, PIE and partial RELRO
```
checksec death_star_computer.bin
[*] '/root/workspace/vuln/midterm/ctfd/robbie/death_star_computer.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

There is a win function in the binary and when we look at it, there is something familiar about it.
```
0000153a  int64_t win(int64_t arg1 @ r13, int64_t arg2 @ r14, int64_t arg3 @ r15)
```

This same thing was seen in a challenge for class earlier in the semester. The challenge was a ret2csu that leveraged the universal gadget. So I checked to see is the binary had csu_init. It didn't, oh well.

If you just run the program, it gives you a menu.
```
1: Enter target coordinates
2: Display current target
3: Fire
```

If you choose 1 it gives you a list of 'locations'. The returns you to the menu once you select one. There you can display the current target. If you choose this one it displays a number. 
```
1: Enter target coordinates
2: Display current target
3: Fire
2
Target Coordinates => 274877911893
```

Looking at these things in binja we can see that choosing a number triggers a switch statement, choosing a number sets a variable to a function associated with that number in the switch case. Then if display is chosen the switch case prints out that variable which is the location of the function. 

Leaking the address of the function is useful to us. 

Choosing the fire option calls the variable you set before which calls the function it's pointing to. This can beuseful to trigger an exploit if we can get one into the function, possibly at one of the previous steps.
