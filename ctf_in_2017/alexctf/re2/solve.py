from pwn import *
import sys, time

context.binary = "./re2"
#context.log_level = "debug"
st = "peda$ "
gdb = process(["gdb", "-q", "./re2"])
gdb.sendlineafter(st, "b *0x400C75")     # cmp
gdb.sendlineafter(st, "peda set option ansicolor off")
gdb.sendlineafter(st, "r " + "A" * 0x40)
prompt = "=> "
flag = ''
char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'_-+{}!@#$"
try:
    for cnt in xrange(0x40):
        gdb.recvuntil("RAX: ")
        byte = int(gdb.recvuntil(" ")[:-1], 0)
        flag += chr(byte)
        gdb.sendlineafter(st, "set $rdx=" + str(byte))
        gdb.sendlineafter(st, "c")
except:
    print flag
