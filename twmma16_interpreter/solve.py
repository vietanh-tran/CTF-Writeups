#!/usr/bin/env python3

from pwn import *

exe = ELF("./befunge")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
'''
always us to insert 0x52 bytes per command
but each command is in a 0x50 chunk
25 commands * 0x50 chunks -> 0x7d0 (200) bytes of command

doesn't zero out stack after the last input?




program - 0x00302040
end - 0x00302810

the numer of stack over/under flows can be numbered


integer overflow
'''