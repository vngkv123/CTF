## Write-up for Plaid CTF 2018
## Roll a d8
Bug is in builtin `Array.prototype.from` CSA routine.
Invalid length getter
Custom `Symbol.iterator` can shrink Array's length and this will give us OOB R/W primitives.
Using unboxed array to leak/overwrite value to get arbitrary R/W.
Solve code is based on 
* https://github.com/uknowy/jsExploit_CTF/blob/master/PCTF2018/d8_exploit.js
* https://github.com/theori-io/zer0con2018_bpak/blob/master/code/exploit.js
