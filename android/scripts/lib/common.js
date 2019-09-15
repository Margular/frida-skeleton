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

function SendWithDate(data) {
    send(Date() + " " + data);
}

function ImplementationWrapper(method, func) {
    var params = [];

    if (func.length > 0) {
        for (var i = 0; i < func.length; i++) {
            params[i] = "_param" + i + "_";
        }
    }

    var impl = method + ".implementation = function (" + params.join() + ") {\n";
    impl += "SendWithDate(\"";

    // funcDetail for log function name and parameters
    var funcDetail = method + "(\" + ";

    if (params.length > 0) {
        funcDetail += params[0];

        for (var i = 1; i < func.length; i++) {
            funcDetail += " + \", \" + " + params[i];
        }
    }

    funcDetail += " + \")";

    impl += funcDetail;
    impl += "\");\n";

    impl += "var ret = " + func.name + ".call(this, " + params.join() + ");\n";
    impl += "SendWithDate(\"" + funcDetail + " => \" + ret);\n";
    impl += "return ret;\n";
    impl += "};\n";

    eval(impl);
}
