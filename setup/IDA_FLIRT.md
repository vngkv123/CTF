# IDA FLIRT
**Usage**
```
root@6c7f37ea6051:/shared/flair/bin/linux# python usage.py
[*] How to use?
[*] ./pelf [static library file] -> make *.pat file
[*] if you get unknwon relocation type N Error, './pelf -rN:0:0 [static library file] *.pat'
[*] ./sigmake *.pat *.sig
[*] if you get 'libstdcpp_x86.sig: modules/leaves: 1132/1781, COLLISIONS: 2' error like this
[*] use 'python ./collisions.py [src] [dst]'
```
