var Format = {
    pretty: function (obj) {
        if (typeof obj === "string") {
            return obj;
        }

        // byte array
        if (obj.__proto__ === Java.array('byte', []).__proto__) {
            return "<[B> " + Conversion.bytes2hex(obj);
        }

        return obj;
    }
};
