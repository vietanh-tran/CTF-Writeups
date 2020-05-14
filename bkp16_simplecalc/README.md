# Boston Key Part 2016 Simple Calc

Looking over ```checksec```...

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

```PIE``` is disabled but ```NX``` is. We'll have to resort to return oriented programing.

As the name implies, this is a calculator, so we have sever options on the menu :
- ```addition```
- ```substraction```
- ```multiplication```
- ```division```
- ```save and exit```

Looking over these functions, they don't look particularly weird, except that either ```operand``` has to be ```> 39```.
Every result is stored as an integer on a chunk.

```c
      if (choice == 1) {
        adds();
        *(undefined4 *)((long)i * 4 + (long)chunk) = add._8_4_;
      }
```

When we exit the program, our values will be copied onto the stack and the chunk will be freed.

```c
            else {
              if (choice == 5) {
                memcpy(buf,chunk,(long)(nrcalcs << 2));
                free(chunk);
                return 0;
```
We can overflow and append a ```ropchain``` at ```ret``` if we supply a big enough ```nrcalcs``` value.
I used ```ROPgadget``` to craft a ```ropchain```. There are some slight modifications though:

- since our ropchain is ```64bit``` but we can add values 4 bytes a time, our "/bin//sh" string has to be split into 2.
- after every 4 byte value we have to insert 4 bytes of ```\x00``` for aligment. We will make an integer overflow for this.
- our "/bin//sh" string must not be surrounded with ```\x00\x00\x00\x00```
- when overflowing the stack up until ```ret```, we will modify the ```chunk``` pointer, which is on the stack. If we put a random data, we will crash in ```free```. We will overflow with a bunch of 0s because when ```free``` is called with ```0``` as argument it doesn't do anything.

```bash
Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> $ whoami
root
```