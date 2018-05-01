from pwn import *
data = open("./test", "r").read()

for i in xrange(len(data)):
    try:
        fp = open("bf", "w")
        fp.write(data[i:])
        fp.close()
        p = process(["./Echo", "bf"])
        print p.recv(timeout=1)
    except:
        p.close()

