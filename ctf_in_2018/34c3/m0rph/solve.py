from pwn import *
import re
import string

p = process(["gdb", "-q",  "./morph"])

def c(cmd):
    p.sendlineafter("peda$ ", cmd)

argv_base = 0x7fffffffe77b
slots = [0, ]

p.sendline("peda set option ansicolor off")
c("b *0")
c("r")
c("d")
c("code")
c("b *($code + 0xb95)")
c("b *($code + 0xbc6)")
c("r {0}".format(string.letters[:23]))

flag = ''
count = 0

while True:
    p.recvuntil("=>")
    p.recvuntil(":")
    code = p.recvuntil("\n")[:-1]
    if "cmp" in code and "al," in code:
        count += 1
        t = re.findall(r"0x[0-9a-f]{2}", code)[0]
        flag += t[2:].decode("hex")
        print flag
        c("set $al={0}".format(t))
        if count == 23:
            break
        c("c")
        p.recvuntil("arg[0]: ")
        slots.append(int(p.recvuntil(" ")[:-1], 0) - argv_base)
        print slots
    
    c("si")
    
rflag = [0] * 23
for i in xrange(23):
    rflag[slots[i]] = ord(flag[i])

print "".join(map(chr, rflag))
p.close()
