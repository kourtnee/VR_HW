from pwn import * 
p=remote("cse4850-bin8.chals.io", 443, ssl=True, sni="cse4850-bin8.chals.io")
p.interactive()
