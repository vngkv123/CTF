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

    send("ret: " + ret);

}, "int", ["pointer", "pointer", "pointer", "pointer"]));

Java.perform(function (){
	var sys = Java.use("java.lang.System");
	sys.exit.overload("int").implementation = function(v1){
		send("Exit bypass");
	}
});

Interceptor.attach(Module.findExportByName("libc.so", "strncmp"), {
    onEnter: function (args) {
        if( args[2].toInt32() == 0x17 ){
			send("secret : " + Memory.readUtf8String(args[1]));
		}
    },
    onLeave: function (retval) {
    }
});
