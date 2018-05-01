from pwn import *
'''
p = process(["./right_or_left"])
p.send("A" * 0x2000)
p.interactive()
'''

d = open("./list", "r").read().replace(",", "")
d =  d.split("\n")
data = ''
for i in d:
    if not i:
        break
    it = int(i, 0)
    if it >= 0x20 and it < 0x80:
        data += chr(it)

print data
