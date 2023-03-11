# bin9:Solution(attempt)

This challenge is a blind rop challenge. We aren't given a binary, we just have to work with the remote server to try to expoit it. I heard that someone had to leak the entire binary in order to solve it. 

My first step was to try to find the overflow, so I used the program I have saved for this exact reason called overflow.py, I just put the remote server address to the challenge where the process goes. 

According to that, it took 40 bytes to overflow the buffer.

This is what we get when we connect to the server:
```
python3 solve.py
[+] Opening connection to cse4850-bin9.chals.io on port 443: Done
[*] Switching to interactive mode
That's not how you count down
It's 3 2 1
                                       _,'/
                                  _.-''._:
                          ,-:`-.-'    .:.|
                         ;-.''       .::.|
          _..------.._  / (:.       .:::.|
       ,'.   .. . .  .`/  : :.     .::::.|
     ,'. .    .  .   ./    \ ::. .::::::.|
   ,'. .  .    .   . /      `.,,::::::::.;\
  /  .            . /       ,',';_::::::,:_:
 / . .  .   .      /      ,',','::`--'':;._;
: .             . /     ,',',':::::::_:'_,'
|..  .   .   .   /    ,',','::::::_:'_,'
|.              /,-. /,',':::::_:'_,'
| ..    .    . /) /-:/,'::::_:',-'
: . .     .   // / ,'):::_:',' ;
 \ .   .     // /,' /,-.','  ./
  \ . .  `::./,// ,'' ,'   . /
   `. .   . `;;;,/_.'' . . ,'
    ,`. .   :;;' `:.  .  ,'
   /   `-._,'  ..  ` _.-'
  (     _,'``------''
   `--''
The Falcon 9 Heavy is one of the most powerful operational rockets to date and its reusable
------------------------------------------------------
| .PLT: 0x401020 | STOP_GADGET START 0x401080 |
| BROP_GADGET START 0x401462 | BLAST_OFF 0x404020 |
------------------------------------------------------
Please enter the launch codes to start: $  
```

The output appears to be the same every time. 
