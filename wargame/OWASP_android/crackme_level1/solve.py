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
/*
    Java.perform(function () {
        var jstr = Java.use("sg.vantagepoint.a.c");

        jstr.a.implementation = function(){
            console.log("a bypass");
            return false;
        };
        jstr.b.implementation = function(){
            console.log("b bypass");
            return false;
        };
        jstr.c.implementation = function(c){
            console.log("c bypass");
            return false;
        };
    });

    Java.perform(function () {
        var debug = Java.use("sg.vantagepoint.uncrackable1.MainActivity");
        debug.a.implementation = function(v1){
            console.log("Debug bypass");
            return false;
        }
    });
*/
    Java.perform(function() {

        bClass = Java.use("sg.vantagepoint.uncrackable1.b");
        bClass.onClick.implementation = function(v) {
         console.log("[*] onClick");
        }

        aaClass = Java.use("sg.vantagepoint.a.a");
        aaClass.a.implementation = function(arg1, arg2) {
            retval = this.a(arg1, arg2);
            password = ''
            for(i = 0; i < retval.length; i++) {
               password += String.fromCharCode(retval[i]);
            }

            console.log("[*] Decrypted: " + password);
            return retval;
        }
        console.log("[*] sg.vantagepoint.a.a.a modified");

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
