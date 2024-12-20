# all function in lib.so iteration
# js
# MK

setTimeout(function () {
Java.perform(function() {
    // Enumerate all loaded modules in the target process
    const modules = Process.enumerateModules();

    // Iterate over each module
    modules.forEach(function(module) {
        console.log("Module Name:", module.name);
        console.log("Base Address:", module.base, " | Size:", module.size);

        try {
            // Enumerate exports (functions) in the current module
            const exports = Module.enumerateExports(module.name);
            
            // Print each function name and address in the current module
            exports.forEach(function(exp) {
                if (exp.type === "function") {
                    console.log("    Function name:", exp.name, "| Address:", exp.address);
                }
            });
        } catch (e) {
            console.log("    Error accessing exports for module:", module.name);
            console.log("    Error:", e.message);
        }

        console.log("\n"); // Line break between modules for readability
    });
});
},500);
