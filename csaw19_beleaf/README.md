# CSAW 2019 beleaf

If we run the binary, it will ask for the actual flag, which means we have to derive it solely from the binary.

```c
  printf("Enter the flag\n>>> ");
  __isoc99_scanf(&DAT_00100a78,local_98);
  len = strlen(local_98);
  if (len < 0x21) {
    puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  i = 0;
  while (i < len) {
    lVar1 = FUN_001007fa((ulong)(uint)(int)local_98[i]);
    if (lVar1 != *(long *)(&DAT_003014e0 + i * 8)) {
      puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    i = i + 1;
  }
  puts("Correct!");
```

The input has to be at least 0x21 bytes. It seems like a call to a function is made for each character, and the return variable is compared to a constant in memory.

Looking into memory, the first 0x21 values that the function return value is compared to are:

```
01 09 11 27 02 00 12 03 
08 12 09 12 11 01 03 13
04 03 05 15 2e 0a 03 0a
12 03 01 2e 16 2e 0a 12
06
```
Looking at the other function:

```c
  local_10 = 0;
  while ((local_10 != -1 && ((int)param_1 != *(int *)(&DAT_00301020 + local_10 * 4)))) {
    if ((int)param_1 < *(int *)(&DAT_00301020 + local_10 * 4)) {
      local_10 = local_10 * 2 + 1;
    }
    else {
      if (*(int *)(&DAT_00301020 + local_10 * 4) < (int)param_1) {
        local_10 = (local_10 + 1) * 2;
      }
    }
  }
  return local_10;
```

It seems like it will keep searching until ```(int)param_1 === *(int *)(&DAT_00301020 + local_10 * 4)))``` and will return local_10, the offset.

We simply have to replace local_10 with our 0x31 values and find the values at those addresses.

```bash
$ ./beleaf
Enter the flag
>>> flag{we_beleaf_in_your_re_future}
Correct!
```