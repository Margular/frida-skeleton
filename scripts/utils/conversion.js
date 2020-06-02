var Conversion = {
    hex2bytes: function (hex) {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return bytes;
    },

    bytes2hex: function (bytes) {
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push(((bytes[i] >>> 4) & 0xF).toString(16).toUpperCase());
            hex.push((bytes[i] & 0xF).toString(16).toUpperCase());
        }
        return hex.join("");
    }
};
