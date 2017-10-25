import sys
from pwn import *

if len(sys.argv) != 3:
    log.warn("Usage : {} [src] [dst]".format(sys.argv[0]))
    sys.exit()

fp = open(sys.argv[1], "r")
new_target = open(sys.argv[2], "w")
exc = fp.readlines()
chk = True
for _exc in exc:
    if ";" in _exc:
        continue
    if chk and _exc != "\n":
        chk = False
        new_target.write("+" + _exc)
        continue
    if _exc != "\n":
        new_target.write(_exc)
    if _exc == "\n":
        chk = True
        new_target.write("\n")
        continue

fp.close()
new_target.close()
