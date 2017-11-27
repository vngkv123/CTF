from z3 import *
import sys
import string
import struct

flag = "\x8b\xce\xb0\x89\x7b\xb0\xb0\xee\xbf\x92\x65\x9d\x9a\x99\x99\x94\xad\xe4\x00"
# 5 x 5 matrix
s = Solver()

matrix = [BitVec('matrix%d' % i, 8) for i in range(25)]     # my flag
strings = [BitVec('strings%d' % i, 8) for i in range(25)]     # my flag

flag_set = "TUCTF{"
'''
for i in xrange(6):
    s.add(matrix[i] == ord(flag_set[i]))
s.add(matrix[24] == ord("}"))

for i in xrange(25):
    m = (i * 2) % 25
    f = (i * 7) % 25
    s.add(matrix[((m/5) * 5) + (m%5)] == strings[f])
'''
s.add(matrix[0] == ord("T"))
s.add(matrix[11] == ord("U"))
s.add(matrix[22] == ord("C"))
s.add(matrix[8] == ord("T"))
s.add(matrix[19] == ord("F"))
s.add(matrix[5] == ord("{"))
s.add(matrix[14] == ord("}"))

s.add(matrix[0] + matrix[24] == ord(flag[0]))
s.add(matrix[11] + matrix[2] == ord(flag[1]))
s.add(matrix[22] + matrix[21] == ord(flag[2]))
s.add(matrix[8] + matrix[16] == ord(flag[3]))
s.add(matrix[19] + matrix[7] == ord(flag[4]))
s.add(matrix[5] + matrix[13] == ord(flag[5]))
s.add(matrix[14] + matrix[10] == ord(flag[6]))
s.add(matrix[18] + matrix[17] + matrix[3] == ord(flag[7]))
s.add(matrix[4] + matrix[20] + matrix[1] == ord(flag[8]))
s.add(matrix[18] + matrix[10] == ord(flag[9]))
s.add(matrix[20] + matrix[7] == ord(flag[10]))
s.add(matrix[4] + matrix[21] == ord(flag[11]))
s.add(matrix[3] + matrix[2] == ord(flag[12]))
s.add(matrix[15] + matrix[10] == ord(flag[13]))
s.add(matrix[9] + matrix[7] == ord(flag[14]))
s.add(matrix[23] + matrix[13] == ord(flag[15]))
s.add(matrix[12] + matrix[2] == ord(flag[16]))
s.add(matrix[6] + matrix[21] == ord(flag[17]))

print s.check()
m = s.model()
print m

seq = [0, 11, 22, 8, 19, 5, 16, 2, 13, 24, 10, 21, 7, 18, 4, 15, 1, 12, 23, 9, 20, 6, 17, 3,14]
val2 = [84, 85, 67, 84, 70, 123, 53, 121, 53, 55, 51, 109, 53, 95, 48, 102, 95, 52, 95, 100, 48, 119, 110, 33 ,125]
flag = ''
for i in val2:
    flag += chr(i)
print flag
