from pwn import *

chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'_-+{}!@#$"

gdb = process(["gdb", "./unknown"])
#context.log_level = "debug"
gdb.recvuntil("peda$ ")
gdb.sendline("b *0x0000000000401C86")
gdb.sendline("b *0x0000000000401F2E")

def check(args, cnt):
    gdb.sendline("r \"" + "".join(args) + "\"")
    #gdb.recvuntil("=> ")
    #res = gdb.recvline()
    for i in xrange(cnt):
        gdb.sendlineafter("peda$ ", "c")
    gdb.recvuntil("=> ")
    res = gdb.recvline()
    if "0x401c86" in res:
        print "[+] Nope : " + "".join(args)
        return False
    if "0x401f2e" in res:
        print "[+] Correct : " + "".join(args)
        return True


flag = "TUCTF{w3lc0m3_70_7uc7f_4nd_7h4nk_y0u_f0" + "A" * 16 + "}"
argv = list("A" * 56)
#argv = list(flag)
for index in xrange(56):
    for byte in chars:
        argv[index] = byte
        chk = check(argv, index)
        gdb.recvuntil("peda$ ")
        if not chk:
            continue
        if chk:
            break
