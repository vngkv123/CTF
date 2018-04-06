from pwn import *
import sys, time
import random

def pow_solver(chal):
    cset = "".join(chr(byte) for byte in xrange(256))
    while True:
        sol = "".join(random.choice(cset) for _ in xrange(4))
        if sha256(chal + sol).digest().startswith('\0\0\0'):
            p.send(sol)
            break

if len(sys.argv) == 1:
    p = process(["./heapstorm2"])
#    p = process(["python", "./pow.py"])

else:
    p = remote("202.120.7.205", "5655")

def allocate(size):
    p.sendlineafter("Command: ", "1")
    p.sendlineafter("Size: ", str(size))

def update(idx, size, data):
    p.sendlineafter("Command: ", "2")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Content: ", data)

def delete(idx):
    p.sendlineafter("Command: ", "3")
    p.sendlineafter("Index: ", str(idx))

def view(idx):
    p.sendlineafter("Command: ", "4")
    p.sendlineafter("Index: ", str(idx))

p.interactive()
