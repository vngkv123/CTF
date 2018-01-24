/*
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

// ----------------------------------------------------------------------- //

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
*/
// ----------------------------------------------------------------------- //

Java.perform(function () {
    var st = Java.use("o.vaehekua");
    st.weicighi.overload("int", "int", "int").implementation = function(v1, v2, v3) {
        send("weicighi is hooked...");
		ret = this.weicighi(v1, v2, v3);
		send("secret : " + ret)
		return ret;
    };
});

Java.perform(function () {
    var st = Java.use("java.io.File");
    st.delete.implementation = function() {
        send("delete is hooked...");
		return true;
    };
});

