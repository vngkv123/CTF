Hey guys, this is a ChakraCore Vulnerability Challenge.Well,I am not expecting you to find a 0day in ChakraCore. In fact, i patch the master ChakraCore code and create a new Vulnerabilities where it doesn't exist. I provide the patch file here, and you can download the master ChakraCore code from github.
https://github.com/Microsoft/ChakraCore

I have provided the compiled binaries under Windows. In addition, please note that we do not accept unexpected solutions (for example, other 0 days or 1 days). You need to use my vulnerability patch to exploit.

First, you need to find the vulnerability and make a vulnerability analysis.
Second, you need to write a vulnerability exploit. The role of exploits does not matter, but you must implement control RIP with 0x4141414141414141 in the Win10 Build 201802 VM that can be downloaded from https://developer.microsoft.com/en-us/windows/downloads/virtual-machines.
Finally, you need to provide me with complete exploit code and screen shots that demonstrate successful exploited.

Mitigation:ASLR DEP CFG
