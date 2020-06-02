var Conversion = {
    /**
     * Convert hex string to byte array
     * @example
     * // returns [156,255,90,67]
     * JSON.stringify(Conversion.hex2bytes('9CFF5A43'));
     * @param {String} hex
     * @returns {[]}
     */
    hex2bytes: function (hex) {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return bytes;
    },

    /**
     * Convert byte array to hex string
     * @example
     * // returns 9CFF5A43
     * Conversion.bytes2hex([156, -1, 90, 67]);
     * @param {[]} bytes
     * @returns {string} hex string
     */
    bytes2hex: function (bytes) {
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push(((bytes[i] >>> 4) & 0xF).toString(16).toUpperCase());
            hex.push((bytes[i] & 0xF).toString(16).toUpperCase());
        }
        return hex.join("");
    }
};
