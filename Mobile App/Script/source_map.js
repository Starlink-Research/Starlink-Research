# source map print
# js
# MK

setTimeout(function () {

// Specify the module and function offset
const moduleName = "libhermes.so";
const functionOffset = {put your sourcemap address}; //sourcemap

// Calculate the absolute address of the function to hook
const targetAddress = Module.findBaseAddress(moduleName).add(functionOffset);

// Hook the function and log arguments
Interceptor.attach(targetAddress, {
    onEnter: function (args) {
        console.log("Called function sourcemap in libhermes.so");

        // Print arguments based on expected types (adjust as needed)
        // For example, if you expect an integer, pointer, or string:
        console.log("Arg1 (int):", args[0]);
        console.log("Arg2 (pointer):", args[1]);
        console.log("Arg3 (string):", args[2]); 

        // Optionally, print a backtrace to see the calling flow
        console.log("Backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n"));
    },
    onLeave: function (retval) {
        // Optionally, print the return value
        console.log("Return value:", retval);
    }
});
},400);
