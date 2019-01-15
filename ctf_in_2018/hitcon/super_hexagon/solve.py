from pwn import *
import sys, time

p = remote("localhost", 6666)

#p.sendline("-32")
#p.sendline(p64(0x400104))

p.interactive()
