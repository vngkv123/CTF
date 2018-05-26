from pwn import *

out = '''
B80C91FE70573EFE
BEED92AE7F7A8193
7390C17B90347C6C
AA7A15DFAA7A15DF
526BA076153F1A32
545C15AD7D8AA463
526BA076FBCB7AA0
7D8AA4639C513266
526BA0766D7DF3E1
AA7A15DF9C513266
1EDC38649323BC07
7D8AA463FBCB7AA0
153F1A32526BA076
F5650025AA7A15DF
1EDC3864B13AD888
'''.replace("\n", "")

out_small = ''
for i in out:
    if ord(i) >= ord("A") and ord(i) <= ord("Z"):
        out_small += chr(ord(i) + 0x20)
        continue
    out_small += i

count = 0
temp = ''
conv_list = []
for i in out_small:
    if count % 8 == 0 and count != 0:
        conv_list.append(temp)
        temp = ''
    temp += i
    count += 1

#context.log_level = "debug"

flag = ''
for byte in conv_list:
    for _ in xrange(0x21, 0x80):
        p = process(["./babyre"])
        p.sendline("abcdabcd")
        p.sendline("10")
        p.sendline(chr(_) * 4)
        p.recvuntil("\n")
        res = p.recvline()[:-1]
        p.close()
        if res == byte:
            print "[-] found : " + chr(_)
            flag += chr(_)
            break

print flag
