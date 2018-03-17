#! /usr/bin/python3
def oo000 ( array ) :
 while True :
  ii = 0
  for oOOo in range ( 8 ) :
   O0 = yield None
   # assert bit == 0 or bit == 1
   if O0 == - 1 :
    array . append ( ii )
    array . append ( oOOo )
   ii += O0 << oOOo
  array . append ( ii )
  if 70 - 70: oo0 . O0OO0O0O - oooo
  if 11 - 11: ii1I - ooO0OO000o
def ii11i ( img_data ) :
 oOooOoO0Oo0O = [ ]
 for oOOo in range ( 0x100 ) :
  iI1 = 0
  for i1I11i in range ( 8 ) :
   if oOOo & 1 :
    iI1 += 1
   oOOo >>= 1
  oOooOoO0Oo0O . append ( iI1 )
 OoOoOO00 = [ 7 , 7 , 6 , 5 , 5 , 4 , 4 , 4 , 4 , 4 , 4 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 3 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 ,
 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 2 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 ]
 if 27 - 27: OOOo0 / Oo - Ooo00oOo00o . I1IiI
 o0OOO = img_data [ : 0x36 ]
 img_data = img_data [ 0x36 : ]
 assert len ( img_data ) == 1024 * 1024 * 3
 for iIiiiI in range ( 3 ) :
  for oOOo in range ( 1024 ) :
   if 23 - 23: iii1II11ii * i11iII1iiI + iI1Ii11111iIi + ii1II11I1ii1I + oO0o0ooO0 - iiIIIII1i1iI
   for i1I11i in range ( 1024 ) :
    o0oO0 = img_data [ ( 1024 * oOOo + i1I11i ) * 3 + iIiiiI ]
    oo00 = 0
    for o00 in range ( 4 ) :
     for Oo0oO0ooo in range ( 4 ) :
      if o00 == 0 and Oo0oO0ooo == 0 :
       continue
      if oOOo - o00 < 0 or i1I11i - Oo0oO0ooo < 0 :
       ii = 0xff
      else :
       ii = img_data [ ( 1024 * ( oOOo - o00 ) + ( i1I11i - Oo0oO0ooo ) ) * 3 + iIiiiI ]
      oo00 += oOooOoO0Oo0O [ ii ]
    if oo00 < 60 :
     o0oOoO00o = 0
     i1 = OoOoOO00 [ oo00 ]
    else :
     o0oOoO00o = 1
     i1 = OoOoOO00 [ 120 - oo00 ]
    for oOOoo00O0O in range ( 8 ) :
     O0 = o0oO0 & 1
     o0oO0 >>= 1
     yield O0 , i1 , o0oOoO00o
     if 15 - 15: I11iii11IIi
     if 93 - 93: O0I11i1i11i1I * oo / OOO0O / I1ii * iiIIIII1i1iI + Oo
def OOo0o0 ( bit_yield , out_buf ) :
 O0OoOoo00o = False
 iiiI11 = 0
 OOooO = 0
 OOoO00o = 0xff
 try :
  while True :
   O0 , i1 , o0oOoO00o = next ( bit_yield )
   if 9 - 9: Oo - I11iii11IIi % ooO0OO000o % ii1I
   i1iIIi1 = OOoO00o >> i1
   ii11iIi1I = OOoO00o - i1iIIi1
   if 6 - 6: iii1II11ii * O0I11i1i11i1I
   if O0 == o0oOoO00o :
    OOoO00o = ii11iIi1I
   else :
    OOoO00o = i1iIIi1
    OOooO += ii11iIi1I
    if 67 - 67: I1ii - ii1II11I1ii1I * i11iII1iiI % i11iII1iiI % iiIIIII1i1iI * iii1II11ii
   if OOooO & 0x100 :
    OOooO = OOooO & 0xff
    out_buf . send ( 1 )
    if iiiI11 > 0 :
     for i1IIiiiii in range ( iiiI11 - 1 ) :
      out_buf . send ( 0 )
     iiiI11 = 0
    else :
     O0OoOoo00o = False
   while OOoO00o & 0x80 == 0 :
    if OOooO & 0x80 :
     o00o = 1
     OOooO = OOooO & 0x7f
    else :
     o00o = 0
     if 41 - 41: ooO0OO000o + OOO0O + oO0o0ooO0 - oo
    if O0OoOoo00o :
     if o00o == 1 :
      iiiI11 += 1
     else :
      out_buf . send ( 0 )
      for i1IIiiiii in range ( iiiI11 ) :
       out_buf . send ( 1 )
      iiiI11 = 0
    else :
     if o00o == 1 :
      out_buf . send ( 1 )
     else :
      O0OoOoo00o = True
    OOoO00o <<= 1
    OOooO <<= 1
    if 77 - 77: Ooo00oOo00o . oo % I1ii
 except StopIteration :
  OOooO += 0x40
  if OOooO & 0x100 :
   out_buf . send ( 1 )
   for oOOo in range ( iiiI11 + 2 ) :
    out_buf . send ( 0 )
  elif O0OoOoo00o :
   out_buf . send ( 0 )
   for oOOo in range ( iiiI11 ) :
    out_buf . send ( 1 )
   out_buf . send ( 1 if OOooO & 0x80 else 0 )
   out_buf . send ( 1 if OOooO & 0x40 else 0 )
   if 42 - 42: ii1II11I1ii1I - ooO0OO000o / oo0 + oO0o0ooO0 + I1IiI
   if 17 - 17: ii1II11I1ii1I . Ooo00oOo00o . iI1Ii11111iIi
if __name__ == '__main__' :
 with open ( "flag.bmp" , 'rb' ) as IIi :
  i1I11 = IIi . read ( )
  if 26 - 26: oo0
 OO0O00 = ii11i ( i1I11 )
 buffer = bytearray ( )
 ii1 = oo000 ( buffer )
 ii1 . send ( None )
 if 57 - 57: I11iii11IIi % ii1I
 OOo0o0 ( OO0O00 , ii1 )
 if 61 - 61: O0I11i1i11i1I . oooo * Oo . I1ii % Ooo00oOo00o
 ii1 . send ( - 1 )
 with open ( 'compressed_data' , 'wb' ) as IIi :
  IIi . write ( i1I11 [ : 0x36 ] )
  IIi . write ( buffer )
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
