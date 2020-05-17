# CSAW 2019 babyboi

Running ```checkscec```:

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

In this challenge, we are given the source code and a libc file. Looking over the source code, there is a call to ```gets()```. Easy buffer overflow.

```c
  char buf[32];
  printf("Hello!\n");
  printf("Here I am: %p\n", printf);
  gets(buf);
```

We're also given a leak of ```printf()``` when we run the program. Using that leak we will calculate ```system()``` and find ```"/bin/sh"``` and perform a ```ret2libc``` attack. We will need to load the string in ```RDI``` so I'll use a gadget ```pop rdi, ret``` found in the same libc file.