from pwn import *
import sys, time

if len(sys.argv) == 1:
    p = process([""])

else:
    p = remote("47.98.57.30", "4279")

p.interactive()
