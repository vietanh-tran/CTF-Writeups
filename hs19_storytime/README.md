# HS 2019 storytime

Looking at ```checksec```:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We only have to defeat ```DEP``` and ```ASLR```. This is the decompilation of the binary:

```c
undefined8 main(void)

{
  undefined local_38 [48];
  
  setvbuf(stdout,(char *)0x0,2,0);
  write(1,"HSCTF PWNNNNNNNNNNNNNNNNNNNN\n",0x1d);
  write(1,"Tell me a story: \n",0x12);
  read(0,local_38,400);
  return 0;
}
```

There's a clear buffer overflow, however how are we supposed to pwn this? We can overflow and modify ```ret``` to call ```write@plt```, where the arguments will be ```(1, write@got, rdx)```. We won't modify ```rdx``` since there are no gadgets for this in the elf binary. However, among the last few lines in the disassembly say that:

```asm
        0040067b e8 20 fe        CALL       write                                            ssize_t write(int __fd, void * _
                 ff ff
        00400680 48 8d 45 d0     LEA        RAX=>local_38,[RBP + -0x30]
        00400684 ba 90 01        MOV        EDX,0x190
                 00 00
        00400689 48 89 c6        MOV        RSI,RAX
        0040068c bf 00 00        MOV        EDI,0x0
                 00 00
        00400691 e8 1a fe        CALL       read                                             ssize_t read(int __fd, void * __
                 ff ff
        00400696 b8 00 00        MOV        EAX,0x0
                 00 00
        0040069b c9              LEAVE
        0040069c c3              RET
```

Which means ```rdx``` will most likely be 0x190 by the time we leak the address of ```write()```. Using the leak, we'll calculate the addresses for ```system()``` and the string ```"/bin/sh"``` and perform a ```ret2libc```.