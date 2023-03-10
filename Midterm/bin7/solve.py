from pwn import * 
p=remote("cse4850-bin7.chals.io", 443, ssl=True, sni="cse4850-bin7.chals.io")
p.interactive()
