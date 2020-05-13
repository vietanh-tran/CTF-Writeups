# TUCTF 2018 Shella-Easy

```
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments

```

We are given a stack address, and there's a call to ```gets```. We can write a ```shellcode``` and overflow until we reach ```ret```, which we will replace with that address. 

However, there is a check, a ```canary``` if you insist. ```(int)*(rbp-0x8)``` has to be ```0xdeadbeef```. Even so, the plan is still same.

```bash
[root@pwn:~/tuctf2018_shella-easy]$ python expl.py 
[+] Starting local process './shella-easy': pid 2226
0xfffead30
[*] Switching to interactive mode
 with a side of fries thanks
$ whoami
root
```