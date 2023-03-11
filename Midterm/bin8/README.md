# bin8:Solution(nope)

The binary is compiled with NX and a stack canary
```
checksec kaufman.bin 
[*] '/root/workspace/vuln/midterm/ctfd/bin8/kaufman.bin'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The advantage of this being a class exercise is that I was able to find out that this was JOP problem before going into it. To check this, I looked at the gadgets in the binary with ropper. There is only one pop gadget and it's not too useful. There are jump gadgets and a lot of add ones. 

The program asks for a review, then it asks for a review number. If the number is under 4 it asks for your name. 

From there I looked at the binary in binja. 

All the input uses fgets, so that's not exploitable. At the start of the program there is a call to the function fill_reviews. When we look at this we see a bunch of dynamic memory allocation.
```
00401350      review_names = malloc(bytes: 0x10)
00401357      int64_t rax_1 = review_names
0040135e      *rax_1 = 'Kade'
00401364      *(rax_1 + 4) = 0x6e
00401374      data_404fc8 = malloc(bytes: 0x10)
0040137b      int64_t rax_3 = data_404fc8
00401382      *rax_3 = 'Jake'
00401388      *(rax_3 + 4) = 0
00401396      data_404fd0 = malloc(bytes: 0x10)
0040139d      int64_t rax_5 = data_404fd0
004013a4      *rax_5 = 'Joel'
004013aa      *(rax_5 + 4) = 0
004013b8      data_404fd8 = malloc(bytes: 0x10)
004013d0      *data_404fd8 = 'Michael'
004013dd      data_404fe0 = malloc(bytes: 0x10)
004013e4      int64_t rax_9 = data_404fe0
004013f5      *rax_9 = 'Charlie'
004013fa      return rax_9
```

All of these have corresponding names. 

I think you can write something for a review that will eventually become an exploit, then use the part where it asks for a name to trigger the exploit maybe. That's as far as I got before I ran out of time.
