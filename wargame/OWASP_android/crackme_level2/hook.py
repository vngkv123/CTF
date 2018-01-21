#!/usr/bin/python
import frida
import sys

package_name = "sg.vantagepoint.uncrackable2"


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message) 

process = frida.get_usb_device().attach(package_name)       # load package ( Target apk file )
script = process.create_script(open("./hook.js").read())        # load JavaScript code to hook Java function
print "[+] Script is Created..."
script.on('message',on_message)
print "[+] Script On..."
script.load()
print "[+] Script is Loaded..."
sys.stdin.read()
