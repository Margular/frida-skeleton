var Format = {
    /**
     * Convert byte array to hex string
     * @param {string} obj
     * @example
     * // returns hello
     * Format.pretty('hello');
     * @param {Object} obj
     * @example
     * // returns 010203
     * Format.pretty(Java.array('byte', [1, 2, 3]));
     * @returns {string}
     */
    pretty: function (obj) {
        if (obj === null || obj === undefined || typeof obj !== 'object') return obj;

        // byte array
        if (obj.__proto__ === Java.array('byte', []).__proto__) {
            var str = Java.use('java.lang.String').$new(obj).toString();
            var validStr = str.replace(/[\x00-\x09\x0B-\x0C\x0E-\x1F\x7F-\x9F]/g, '');
            // need fix: the regexp can not work perfectly
            if (str.length > validStr.length)
                return Conversion.bytes2hex(obj);
            else
                return validStr;
        }

        return obj;
    }
};
