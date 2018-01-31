def HIBYTE(data):
    data = data & 0xff000000
    data = data >> 24
    return data

def calc(data):
    res = ~((~(data & 0xff) | ((data & 0xFF00) >> 8)) & (~((data & 0xFF00) >> 8) | data));
    result = HIBYTE(data) ^ ((data & 0xFF0000) >> 16);
    return res, result

def prt(val):
    st = ''
    for i in val:
        c1, c2 = calc(i)
        st += chr(c1) + chr(c2)
    print st

val = [        625020704,
               274990436,
               1534345504,
               73731176,
               107435040,
               208625010,
               57547381,
               1193298532,
               174394722,
               174457445,
               1331774752,
               274992494,
               1298351648,
               7276911,
               1142948971,
               141449845,
               90774900,
               1394608492,
               376589666,
               326582639,
               493161326]

val2 = [358967112,
               460591969,
               1081033504,
               158079593,
               258559008,
               1293959534,
               1344274529,
               1633754988]
val3 = [1142966885, 90266995, 459477109]

prt(val)
prt(val2)
prt(val3)

headers = open("./headers").read().split("L")
enc = "49L5eL52L5aL79L1bL7bL5aL7cL5bL66L5aL5aL5aL48L5aL6fL1aL55L5aL12L58L5bL5aLeL9L5fL5aL12L59L59L5aLedL68Ld7L78L15L58L5bL5aL82L5aL5aL5bL72La8L78L5aL45L5aL2aL7aL7eL5aL4aL5aL40L5bL5aL5aL34L7aL7fL5aL4aL5aL50L5aL63L5aL47L5aLeLaL58L5aL34L4aL5bL5aL5aL5aL56L5aL78L5bL45L5aL38L58L5eL5aLeL9L5fL5aL2bL7aL78L5aL68L5aL56L58L2aL7aL7eL5aL7bL5aL48L48L2bL6aL4fL5aL4aL58L56L5aL34L4aL4cL5aL5aL5aL54L5aL5aL59L5bL5aL52L5aL5aL5aL40L41L44L5eL4fL58L48L5d".split("L")

fin = ''
for i in headers:
    decrypt = int("0x" + i, 0)
    byte = hex(decrypt)[2:]
    if( len(byte) != 2 ):
        byte = "0" + byte
    fin += chr(int("0x" + byte, 0))
#print fin
fin2 = ''
#fin = fin[:0x720 - 1]
for i in enc:
    decrypt = int("0x" + i, 0) ^ 0x5a
    byte = hex(decrypt)[2:]
    if( len(byte) != 2 ):
        byte = "0" + byte
    fin2 += chr(int("0x" + byte, 0))

fin = fin[:0x720] + fin2 + fin[len(fin2) + 0x720:]

d_file = open("./decrypt.dex", "wb")
d_file.write(fin)
d_file.close()
print fin

