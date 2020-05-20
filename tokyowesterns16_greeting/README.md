# TokyoWesterns 2016 Greetings

Looking at ```checksec```:

```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Looking over the decompilation, there is a clear format string bug:

```c
  printf("Please tell me your name... ");
  iVar1 = getnline(local_54,0x40);
  if (iVar1 == 0) {
    puts("Don\'t ignore me ;( ");
  }
  else {
    sprintf(local_94,"Nice to meet you, %s :)\n",local_54);
    printf(local_94);
  }
```

The getnline function acts as a wrapper to ```fgets()``` that also appends a null character and returns the length of our input with a call to ```strlen()```. Our input is then formatted into another char buffer, with no regards for the length.

There are a bunch of possible ways to solve this, such as leaking a stack address and mofiying ```ret``` to call ```system@plt``` and modifying ```ebp+0x8``` to point to a place in memory where we have a "/bin/sh" string. 

We can also just change the call from ```strlen()``` to actually give call ```system@plt``` instead, with out input as argument. In order to do that, we have to overwrite the address at ```strlen@got``` and return back to the program once again. Since there are no functions left we will just modify a ```dtors entry```.