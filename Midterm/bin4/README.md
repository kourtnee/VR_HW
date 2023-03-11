# bin4:Solution

The binary is compiled with NX and partial RELRO
```
checksec popcorn 
[*] '/root/workspace/vuln/midterm/ctfd/bin4/popcorn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Main has a call to time and srand which is the most common way to create a pseudo random number generator
```
00401214  call    time
00401219  mov     edi, eax
0040121b  call    srand
```

srand sets the initial point for generating pseudo random numbers, then there is a comparison
```
0040125e  cmp     dword [rbp-0x4 {var_c}], 9
00401262  jle     0x401229
```

If the value of var_c is less than or equal to 9 then the rand function gets called. This seems to build some sort of stack structure from the values generated. They are pushed and a counter is added to until it reaches 10 then the program starts to display the propmts.
```
./popcorn
Welcome to unlimited popcorn...Guess the number: 
```

scanf is used for the user input. Attempting to overflow it with a character, even just one, immediately crashes the program. Attempting to overflow with numbers, even increasingly large ones, seemed to lead nowhere.

While attempting to input various things I started to notice a pattern (at least locally), every time I ran the program after 24 tries of input I kept getting a -14. I'm not really sure why, so I kept messing with the input so look for more patterns.

When I spammed input locally I kept getting the number 64, and when I re-entered that into the input prompt it triggered the win function.

Just to check I tried 64 on the remote server:
```
python3 solve.py 
[+] Opening connection to cse4850-bin4.chals.io on port 443: Done
[*] Switching to interactive mode
Welcome to unlimited popcorn...Guess the number: 
$ 64
Popped value: 5285
Welcome to unlimited popcorn...Guess the number:
```

Not the answer, so I went back to analyzing the code for clues. I renamed some variables in binja to try to see what exactly was happening
```
00401289          __isoc99_scanf(format: &data_40204a, &input)
0040128e          int32_t pop = pop()
004012aa          printf(format: "Popped value: %d\n", zx.q(pop))
004012b5          if (pop == input)
004012bc              if (input != 0)
004012bc                  break
004012be      win()
004012ca      return 0
```

The popped value gets printed to the screen and then if the popped value and the user input are equal, it checks to see if the user input is zero. If it's not then the program breaks and the win function is called. 

In order to win we need to know what the popped value is going to be. I'm sure there are many programatic ways to accomplish this, but since I'd already noticed a pattern earlier I tested the theory out. 

I ran the program locally, input '0' 23 times, and then I entered -14. Boom! I got the win function. So I just needed to repeat that on the remote server. 

Surprisingly the number on the remote server was even the same, at the 24th input I entered -14 and got the flag!
```
flag{all_children_3xc3pt_0n3_gr0w_up}
```
