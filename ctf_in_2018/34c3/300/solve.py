from pwn import *
import sys, time

p = process(["./300"])
context.binary = "./300"

p.interactive()
