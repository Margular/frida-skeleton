/*
 * Description: Common functions for common usage.
 * Author: Margular
 * Date: 2020-06-01
 * Version: 2.0
 */

const Common = {
    impl : function (method, func) {
        // store func to global
        if (global.hasOwnProperty("_func_index_"))
            global["_func_index_"]++;
        else
            global["_func_index_"] = 0;

        var func_index = global["_func_index_"];
        var func_name = "_func_" + func_index + "_";
        global[func_name] = func;

        function _pretty_(p) {
            return "Format.pretty(" + p + ")";
        }

        var params = [];

        if (func.length > 0) {
            for (var i = 0; i < func.length; i++) {
                params[i] = "_param" + i + "_";
            }
        }

        var impl = method + ".implementation = function (" + params.join() + ") {\n";
        impl += "send(\"";

        // funcDetail for log function name and parameters
        var funcDetail = method + "(\" + ";

        if (params.length > 0) {
            funcDetail += _pretty_(params[0]);

            for (var j = 1; j < func.length; j++) {
                funcDetail += " + \", \" + " + _pretty_(params[j]);
            }
        } else
            funcDetail += "\"\"";

        funcDetail += " + \")";

        impl += funcDetail;
        impl += "\");\n";
        impl += "var ret = " + func_name + ".call(this";

        if (params.length > 0)
            impl += ", " + params.join() + ");\n";
        else
            impl += ");\n";

        impl += "send(\"" + funcDetail + " => \" + Format.pretty(ret));\n";
        impl += "return ret;\n";
        impl += "};\n";

        console.log(impl);

        eval(impl);
    },

    printBacktrace : function () {
        const android_util_Log = Java.use('android.util.Log');
        const java_lang_Exception = Java.use('java.lang.Exception');
        // getting stacktrace by throwing an exception
        send(android_util_Log.getStackTraceString(java_lang_Exception.$new()));
    },

    // remove duplicates from array
    uniqBy : function (array, key) {
        var seen = {};
        return array.filter(function (item) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    }
};
