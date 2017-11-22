from pwn import *
import sys, time

context.binary = "./main_strip"
#context.log_level = "debug"
gdb = process(["gdb", "-q", "./main_strip"])
gdb.sendline("b *0x47ba23")     # fail
gdb.sendline("b *0x47b976")     # success
gdb.sendline("peda set option ansicolor off")
prompt = "=> "

char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'_-+{}!@#$"
chk = 1
flag = list("A" * 42)

for i in xrange(42):
    for char in char_set:
        flag[i] = (char)
        run_script = "r " + '"' + "".join(flag) + '"'
        gdb.sendline(run_script)

        if i >= 1:
            gdb.recvuntil("RIP: ")
            for hit in xrange(i):
                gdb.sendline("c")
                gdb.recvuntil("RIP: ")
                rip = int(gdb.recvuntil(" ")[:-1], 0)

        if i == 0:
            gdb.recvuntil("RIP: ")
            rip = int(gdb.recvuntil(" ")[:-1], 0)
        if rip == 0x47ba23:
            continue
        if rip == 0x47b976:
            print "find " + "".join(flag)
            break

print "".join(flag)

gdb.close()
