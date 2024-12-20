# hermesRuntimeImpl::call hook
# js
# MK
# runtimePtr and valueToStringAddr are not needed

setTimeout(function () {

let libhermesBaseAddress = Module.findBaseAddress("libhermes.so");
let hermesRuntimeImplCallAddress = libhermesBaseAddress.add(0x8DFCC);
let runtimePtr = Module.findExportByName("libhermes.so", "_ZN8facebook6hermes17makeHermesRuntimeERKN6hermes2vm13RuntimeConfigE");
let valueToStringAddr = Module.findExportByName("libjsi.so", "_ZNK8facebook3jsi5Value8toStringERNS0_7RuntimeE");


Interceptor.attach(hermesRuntimeImplCallAddress, {
    onEnter: function(args) {
        console.log("HermesRuntimeImpl::call intercepted");

        // Extracting arguments
        let func = args[1]; // jsi::Function
        let jsThis = args[2]; // jsi::Value
        let jsArgs = args[3]; // jsi::Value
        let count = args[4]; // size_t count

        // Logging arguments
        console.log(`Function: ${func}`);
        console.log(`jsThis: ${jsThis}`);
        console.log(`jsArgs: ${jsArgs}`);
        console.log(`Count: ${count}`);
        console.log(`runtimePtr: ${runtimePtr}`);
        console.log(`valueToStringAddr: ${valueToStringAddr}`);
        console.log("Backtrace:\n" + Thread.backtrace(this.context, Backtracer.FUZZY)
        .map(DebugSymbol.fromAddress).join("\n"));
        
    }
});

}, 600);
