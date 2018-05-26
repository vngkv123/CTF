from pwn import *

bp = 0x4008b5

p = process(["gdb", "./vm_rel"])
p.sendlineafter("peda$ ", "peda set option ansicolor off")
p.sendlineafter("peda$ ", "b *getchar")
p.sendlineafter("peda$ ", "r")
p.sendlineafter("peda$ ", "d")
p.sendlineafter("peda$ ", "b *0x4008b5")
p.sendlineafter("peda$ ", "c")
p.sendline("09a71bf084a93df7ce3def3ab1bd61f6")
while True:
    try:
        p.recvuntil("RAX: ")
        print p.recvline()[:-1]
        p.sendlineafter("peda$ ", "c")
    except:
        p.interactive()
