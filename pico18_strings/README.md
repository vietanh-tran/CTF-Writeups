# PicoCTF 2018 - Strings

As the name suggests, we use ```strings``` on the binary.
This will spill out a lot of random strings. In order to find the flag, we plug the output into ```grep "pico"```.

```asm
$ strings strings | grep "pico"
picoCTF{sTrIngS_sAVeS_Time_3f712a28}
```
