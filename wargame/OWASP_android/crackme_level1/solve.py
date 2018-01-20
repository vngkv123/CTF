#!/usr/bin/python
import frida
import sys

package_name = "sg.vantagepoint.uncrackable1"


def get_messages_from_js(message, data):
        if message['type'] == 'send':
            print("[*] {0}".format(message['payload']))
        else:
            print(message)


def instrument_debugger_checks():
    hook_code = '''
    Java.perform(function(){
        root = Java.use("sg.vantagepoint.a.c");
        root.a.implementation = function(){
            send("root detection 1 bypass");
            return false;
        }

        root = Java.use("sg.vantagepoint.a.c");
        root.b.implementation = function(){
            send("root detection 2 bypass");
            return false;
        }

        root = Java.use("sg.vantagepoint.a.c");
        root.c.implementation = function(){
            send("root detection 3 bypass");
            return false;
        }

        debug = Java.use("sg.vantagepoint.uncrackable1.b");
        debug.onClick.implementation = function(v1){
            send("Debug bypass");
        }

        secret = Java.use("sg.vantagepoint.a.a");
        secret.a.implementation = function(v1, v2){
            res = this.a(v1, v2);
            send(res);
            pw = ''
            for( var i = 0; i < res.length; i++ ){
                pw += String.fromCharCode(res[i]);
            }
            send(pw);
        }
    });
'''
    return hook_code


process = frida.get_usb_device().attach(package_name)
script = process.create_script(instrument_debugger_checks())
print "[+] Script Created..."
script.on('message',get_messages_from_js)
print "[+] Script On..."
script.load()
print "[+] Script is Loaded..."
sys.stdin.read()
