/*
 * Description: Common functions for common usage.
 * Author: Margular
 * Date: 2019-08-21
 * Version: 1.0
 */

var Class = Java.use("java.lang.Class");
var StringBuilder = Java.use("java.lang.StringBuilder");

/* return values of declared fields of an object
 * o: object to extract
 * parent: a boolean variable that indicates whether to extract parent fields of the object
 */
function extractDeclaredFields(o) {
    var currentClass = Java.cast(o.getClass(), Class);
    var sb = StringBuilder.$new();

    while (currentClass.__proto__.hasOwnProperty('getName')) {
        sb.append(currentClass.getName()).append("=====");
        currentClass.getDeclaredFields().forEach(function(field) {
            field.setAccessible(true);
            sb.append(field.getName()).append(": ").append(field.get(o)).append('---');
        });
        currentClass = currentClass.getSuperclass();
    }

    return sb.toString();
}

function sendWithDate(data) {
    send(Date() + " " + data);
}

function implementationWrapper(method, func) {
    // store func to global
    if (global.hasOwnProperty("_func_index_"))
        global["_func_index_"]++;
    else
        global["_func_index_"] = 0;

    var func_index = global["_func_index_"];
    var func_name = "_func_" + func_index + "_";
    global[func_name] = func;

    var params = [];

    if (func.length > 0) {
        for (var i = 0; i < func.length; i++) {
            params[i] = "_param" + i + "_";
        }
    }

    var impl = method + ".implementation = function (" + params.join() + ") {\n";
    impl += "sendWithDate(\"";

    // funcDetail for log function name and parameters
    var funcDetail = method + "(\" + ";

    if (params.length > 0) {
        funcDetail += params[0];

        for (var i = 1; i < func.length; i++) {
            funcDetail += " + \", \" + " + params[i];
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

    impl += "sendWithDate(\"" + funcDetail + " => \" + ret);\n";
    impl += "return ret;\n";
    impl += "};\n";

    eval(impl);
}
