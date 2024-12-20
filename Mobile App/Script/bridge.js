# 알아서 잘 쓰세요
# js
# MK

Java.perform(function () {
    // Delay the hook by 100 milliseconds
    setTimeout(function () {
        const second = Java.use('com.facebook.react.bridge.CatalystInstanceImpl');
        second.jniCallJSFunction.implementation = function (module, method, args) {
            if (module !== "JSTimers") {
                console.log("module", module);
                console.log("method", method);
                console.log("argument", args);
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
            }
            this.jniCallJSFunction(module, method, args);

        };
        console.log("jniCallJSFunction hook applied after 100ms delay");
    }, 1000);

    Java.use('com.facebook.react.shell.MainReactPackage').getModule.overload('java.lang.String', 'com.facebook.react.bridge.ReactApplicationContext').implementation = function (stringArgument, context) {
        var result = this.getModule(stringArgument, context);
        console.log("getmodule", stringArgument);
        console.log("getmodule context", context);

        try {
            console.log("getmodule result (JSON):", JSON.stringify(result));
        } catch (error) {
            console.log("Error stringifying result:", error);
        }

        console.log("getmodule result (detailed):");
        for (var key in result) {
            if (result.hasOwnProperty(key)) {
                try {
                    console.log(key + ": " + result[key]);
                } catch (innerError) {
                    console.log(key + ": [Error retrieving value] " + innerError);
                }
            }
        }

        return result;
    };
});
