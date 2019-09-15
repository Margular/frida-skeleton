var MainActivity = Java.use("io.github.margular.MainActivity");

function getBestLanguage(lang){
    return this.getBestLanguage("I don't know, but it's not PHP!!!");
};

ImplementationWrapper("MainActivity.getBestLanguage", getBestLanguage);
