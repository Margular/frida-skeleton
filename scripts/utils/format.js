/*
 * Description: Format everything
 * Author: Margular
 * Date: 2020-06-01
 * Version: 1.0
 */

const Format = {
    pretty : function (obj) {
        if (typeof obj === "string") {
            return obj;
        }

        // byte array
        if (obj.__proto__ === Java.array('byte', []).__proto__) {
            // return "<[B> " + Conversion.bytes2hex(obj);
            return JSON.stringify(input);
        }

        return obj;
    }
};
