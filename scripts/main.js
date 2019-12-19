var MainActivity = Java.use("io.github.margular.MainActivity");

implementationWrapper("MainActivity.getBestLanguage", function (lang){
   return this.getBestLanguage("Python3");
});
