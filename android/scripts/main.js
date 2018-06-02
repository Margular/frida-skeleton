var MainActivity = Java.use("io.github.margular.MainActivity");

MainActivity.getBestLanguage.implementation = function() {
    var sendString = Date();
    sendString += "  MainActivity.getBestLanguage()";
    send(sendString);

    var bestLanguage = this.getBestLanguage();
    sendString += " -> " + bestLanguage;
    var newBestLanguage = "Python3";
    sendString += " => " + newBestLanguage;
    sendString += "\n";
    sendString += getStackTrace();
    send(sendString);

    return newBestLanguage;
};
