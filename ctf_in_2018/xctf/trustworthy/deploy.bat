@echo off

REM This batch script should be run as administrator.
REM Deploy dir : <REDACTED>
REM dependency installed : vc redist 2015 x64, python 2.7.14 amd64, pywin32-221 amd64

REM Create directories
mkdir <REDACTED>
mkdir <REDACTED>

REM Creak token
echo <REDACTED> > C:\token.txt

REM Create challenge users
net user ctf <REDACTED> /add
net user victim <REDACTED> /add

REM disable inbound & outbound by default
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

REM enable service port
netsh advfirewall firewall add rule name="chalservice" dir=in action=allow protocol=TCP localport=13337

REM Modify ACLs
icacls C:\token.txt /inheritance:d
icacls C:\token.txt /remove:g "Authenticated Users" /remove:g "Users" /grant victim:(RX)

REM challenge directory contains every program used to run this service
REM and you don't need access to those files
icacls <CHALLENGE_DIRECTORY_REDACTED> /inheritance:d
icacls <CHALLENGE_DIRECTORY_REDACTED> /remove:g "Authenticated Users" /remove:g "Users"

REM Register & run the service, (you won't get a copy of the service.py though)
python <CHALLENGE_DIRECTORY_REDACTED>\service.py install
net start chalsvc


