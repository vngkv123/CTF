#!/usr/bin/python
import frida
import sys

package_name = "sg.vantagepoint.uncrackable3"

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


def instrument_debugger_checks():
    hook_code = '''

    Interceptor.attach(Module.findExportByName("libc.so","strstr"),{
	onEnter: function(args) {
	    this.target = Memory.readUtf8String(args[1]);
	},
	onLeave: function(result) {
	    if(this.target == "frida" || this.target == "xposed")
	    {
                //console.log("frida bypass");
		result.replace(0);
	    }
	}
    });

    var p_pthread_create = Module.findExportByName("libc.so", "pthread_create");
    var pthread_create = new NativeFunction( p_pthread_create, "int", ["pointer", "pointer", "pointer", "pointer"]);
    send("NativeFunction pthread_create() replaced @ " + pthread_create);

    Interceptor.replace( p_pthread_create, new NativeCallback(function (ptr0, ptr1, ptr2, ptr3) {
        send("pthread_create() overloaded");
        //var ret = ptr(0);
	var ret = 0;
        if (ptr1.isNull() && ptr3.isNull()) {
            send("pthread_create is passed");
        } else {
            send("Real pthread_create()");
            ret = pthread_create(ptr0,ptr1,ptr2,ptr3);
        }

        send("ret: " + ret);
        do_hook();

    }, "int", ["pointer", "pointer", "pointer", "pointer"]));

    Java.perform(function () {
        send("java.lang.System.exit() Hooking process");

        var sys = Java.use("java.lang.System");
        sys.exit.overload("int").implementation = function(var_0) {
            send("java.lang.System.exit() is hooked...");
        };

        send("exit Done");
    });

    Java.perform(function (){
	var target = Java.use("sg.vantagepoint.uncrackable3.MainActivity");
	target.verifyLibs.implementation = function(){
		send("verifyLibs is hooked");
	};
	send("verifyLibs Done");
    });

    function do_hook(){
        var foobase = Module.findBaseAddress("libfoo.so");
        var p_xor = foobase.add(0x7224);
        Interceptor.attach( p_xor, {
            onEnter: function(args){
                send("args[0]: " + args[0]);
                send(hexdump(args[0], {
                offset: 0,
                length: 24,
                header: false,
                ansi: true
                }));

                send("args[1]: " + args[1]);
                var secret = hexdump(args[1], {
                    offset: 0,
                    length: 24,
                    header: false,
                    ansi: true
                })
                send(secret);
            },
            onLeave: function(res){
            }
        });
    }
'''
    return hook_code

device = frida.get_usb_device()
pid =  device.spawn([package_name])
session = device.attach(pid)
print '[+] attach'
script = session.create_script(instrument_debugger_checks())
script.on('message', on_message)
script.load()
print '[+] load complete'
device.resume(pid)
sys.stdin.read()
'''
process = frida.get_usb_device().attach(package_name)       # load package ( Target apk file )
script = process.create_script(instrument_debugger_checks())        # load JavaScript code to hook Java function
print "[+] Script is Created..."
script.on('message',on_message)
print "[+] Script On..."
script.load()
print "[+] Script is Loaded..."
sys.stdin.read()
'''
