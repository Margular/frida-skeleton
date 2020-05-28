/*
 * Description: For data flow format conversion.
 * Author: Margular
 * Date: 2020-05-28
 * Version: 1.0
 */

const Conversion = function () {
    function hex2bytes(hex) {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return bytes;
    }

    function bytes2hex(bytes) {
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push(((bytes[i] >>> 4) & 0xF).toString(16).toUpperCase());
            hex.push((bytes[i] & 0xF).toString(16).toUpperCase());
        }
        return hex.join("");
    }

    return {
        hex2bytes : hex2bytes,
        bytes2hex : bytes2hex
    }
}();
