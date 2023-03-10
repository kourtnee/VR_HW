from pwn import * 
p=remote("cse4850-bin4.chals.io", 443, ssl=True, sni="cse4850-bin4.chals.io")
p.interactive()
