var gb_offset = 0x71f0
/*
Java.perform(function () {
    send("java.lang.System.exit() Hooking process");

    var sys = Java.use("java.lang.System");
    sys.exit.overload("int").implementation = function(var_0) {
        send("java.lang.System.exit() is hooked...");
    };

    send("exit Done");
});
*/
/*
Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {

    onEnter: function (args) {
		send("strstr hook process");
		this.dbi = 0;
		var tmp = Memory.readUtf8String(args[0]);
		var target = Memory.readUtf8String(args[1]);
		if( tmp.indexOf("frida") != -1 || tmp.indexOf("xposed") != -1 ){
			send(tmp + " : " + target);
			this.dbi = 1;
		}
	},

    onLeave: function (retval) {
		if( this.dbi == 1 ){
			send("Default : " + retval + " -> 0");
			retval.replace(0);
		}
		return 0;
    }
});
*/
Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {

    onEnter: function (args) {

        this.haystack = args[0];
        this.needle   = args[1];
        this.frida    = Boolean(0);

        haystack = Memory.readUtf8String(this.haystack);
        needle   = Memory.readUtf8String(this.needle);

        if ( haystack.indexOf("frida") != -1 || haystack.indexOf("xposed") != -1 ) {
			//console.log(haystack + " : " + needle);
            this.frida = Boolean(1);
        }
    },

    onLeave: function (retval) {

        if (this.frida) {
            //send("strstr(frida) was patched!! :) " + haystack);
            retval.replace(0);
        }

        return retval;
    }
});
/*
Interceptor.attach(Module.findExportByName("libc.so", "fork"), {
	onEnter: function(args){
		console.log("fork exploit");
	},
	onLeave: function(result){
		result.replace(0);
		return result;
	}
});

var p_raise = Module.findExportByName("libc.so", "fork");
var raise = new NativeFunction(p_raise, 'int', ['void']);
Interceptor.replace(p_raise, new NativeCallback(function (stat) {
	send("raise is replaced...");
    return 0;
}, 'int', ['void']));

var p_exit = Module.findExportByName("libc.so", "_exit");
var exit = new NativeFunction(p_exit, 'void', ['int']);
Interceptor.replace(p_exit, new NativeCallback(function (stat) {
    send("_exit is hooked...");
}, 'void', ['int']));
*/
var offset_anti_debug_x64   = 0x000075f0;
var offset_protect_secret64 = 0x0000779c;
var offset_strncmp_xor64    = 0x000077ec;

function do_hook(){

    var p_foo = Module.findBaseAddress("libfoo.so");
    if (!p_foo) {
        send("p_foo is null (libfoo.so). Returning now...");
        return 0;
    }
    var p_protect_secret = p_foo.add(offset_protect_secret64);
    var p_strncmp_xor64  = p_foo.add(offset_strncmp_xor64);
    send("libfoo.so          @ " + p_foo.toString());
    send("ptr_protect_secret @ " + p_protect_secret.toString());
    send("ptr_strncmp_xor64  @ " + p_strncmp_xor64.toString());


    Interceptor.attach( p_protect_secret, {
        onEnter: function (args) {
            send("onEnter() p_protect_secret");
            send("args[0]: " + args[0]);
        },

        onLeave: function (retval) {
            send("onLeave() p_protect_secret");
         }
    });

    Interceptor.attach( p_strncmp_xor64, {
        onEnter: function (args) {
            send("onEnter() p_strncmp_xor64");
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

        onLeave: function (retval) {
            send("onLeave() p_strncmp_xor64");
            send(retval);
         }
    });
}
/*
var p_raise = Module.findExportByName("libc.so", "raise");
var raise = new NativeFunction( p_raise, "int", ["int"]);
Interceptor.replace( p_raise, new NativeCallback(function ( stat ){
	if( stat == 6 ){
		send("raise(6) is triggered...");
	}
	send("raise hook");
}, "int", ["int"]));
*/

var p_pthread_create = Module.findExportByName("libc.so", "pthread_create");
var pthread_create = new NativeFunction( p_pthread_create, "int", ["pointer", "pointer", "pointer", "pointer"]);
send("NativeFunction pthread_create() replaced @ " + pthread_create);

Interceptor.replace( p_pthread_create, new NativeCallback(function (ptr0, ptr1, ptr2, ptr3) {
    send("pthread_create() overloaded");
    var ret = ptr(0);
    if (ptr1.isNull() && ptr3.isNull()) {
        send("loading fake pthread_create because ptr1 and ptr3 are equal to 0!");
    } else {
        send("loading real pthread_create()");
        ret = pthread_create(ptr0,ptr1,ptr2,ptr3);
    }

    do_hook();

    send("ret: " + ret);

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
