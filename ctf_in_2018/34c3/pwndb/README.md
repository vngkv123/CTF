Challenge is running on fully updated Windows 10 RS3 (Build 1709). The VM was
downloaded from [1].

If you need more information about the remote system, please ask in IRC.

Challenge is running with low IL and served via

    socat -T120 tcp4-l:1337,fork exec:./pwndb.exe

in a bash shell.

Also, because Windows 10 sucks as a server system, we might kill all pwndb.exe
processes every 10 minutes or so. So if your exploit fails, please try again.
If your exploit takes much longer than a few minutes, please let us know and we
might be able to disable the watchdog temporarily.

There is no intended bug in the SQL parser, so you may just trust the
sqlparser.h file.

Flag is in `C:\flag.txt`. Don't assume the challenge process is allowed anything
other than to read this file.

--
[1]: https://developer.microsoft.com/en-us/windows/downloads/virtual-machines
