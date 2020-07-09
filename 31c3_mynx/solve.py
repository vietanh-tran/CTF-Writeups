#!/usr/bin/env python3

from pwn import *

exe = ELF("./mynx")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    # good luck pwning :)

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
		- [5] read our input 0xf7 - OFF BY ONE OVERFLOW!!!!!!!!!!!!!!!!!!!

		2. Remove all comments - DOESN'T ACTUALLY REMOVE ALL COMMENTS

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


			BASICALLY: smallWTF and bigWTF make some kind of consolidation!

							imiplications that remove is not perfect because it doesn't check behind??


		3. Apply filter
			- calls function at [5] with [9] as argument    <--- overwrite to control the instruction pointer


		0. Go back


Filter functions;





can unset bit with onebyte overflow -> 2 ptrs pointing to the same minichunk -> overwrite ptr
'''