orig = open("./re_4eb61221f53827c95ad0b0572812a95c", "r").read()
data = open("./result2.bin", "r").read()

dump = data.replace("\xc8\x18\x40\x00", "\xa0\x0a\x40\x00") + orig[0x2000:]
target = open("./dump.bin", "w")
target.write(dump)
target.close()
