## 一句话简介

frida-skeleton会根据指定的正则表达式持续监听并hook对应的程序，遍历scripts目录下的所有js文件并将它们全部加载用以hook这些程序



## 用法

![](./assets/help.png)



* -i: 自动从github安装对应版本和架构的frida-server，安装是在插入USB后进行的，不会提前安装，frida-server会下载到assets目录下，支持断点续传，并且不会重复下载；下载完之后会自动通过adb push到/data/local/tmp目录下并自动添加执行权限以及在后台运行
* -p PORT: 如-p 8080，会自动利用iptables将所有的TCP流量重定向到安卓的8080端口，并且还会通过adb reverse将安卓上的8080映射到本机的8080，这样就可以在本机用Burp Suite监听8080端口来抓包了（是不是很方便呢）
* -s: 激活spawn模式，默认是attach模式，开启此选项会导致目标进程自动重启，请提前保存重要内容
* -v: debug模式，会输出更多的信息
* regexps: 支持多个正则表达式，frida-skeleton会根据你指定的正则表达式去匹配包名hook对应的程序



## 输出示例

你可以在这里获取示例中的apk：[示例APK](https://github.com/Margular/frida-skeleton/releases)

[![asciicast](https://asciinema.org/a/334653.png)](https://asciinema.org/a/334653)



## 目录结构

* assets: 资源文件，存放图片、frida-server
* lib: python库文件
* logs: 日志文件
* scripts: 这个目录下面的所有js文件都会被加载用来hook对应的程序
* tests: 示例代码，目前只有一个安卓程序



## 特性

### 更简洁的hook代码

原生frida的hook代码：

```javascript
var MainActivity = Java.use("io.github.margular.MainActivity");

MainActivity.getBestLanguage.implementation = function (lang) {
    var sendString = Date();
    sendString += " MainActivity.getBestLanguage(" + lang + ")";
    send(sendString);

    var bestLang = this.getBestLanguage(lang);
    bestLang = "Python3";
    sendString += " => " + bestLang;
    send(sendString);

    return bestLang;
}
```



frida-skeleton的hook代码(路径为`scripts/main.js`)：

```javascript
var MainActivity = Java.use("io.github.margular.MainActivity");

implementationWrapper("MainActivity.getBestLanguage", function (lang){
    return this.getBestLanguage("Python3");
});
```



它们的输出相同，frida-skeleton通过实现一个implementationWrapper使得它会在hook函数的之前、之后都自动地打印日志信息，如下图所示：

![](./assets/frida-skeleton-style-of-hook.png)



## 自动绕过证书绑定

实现证书绕过功能的js文件摘抄自互联网，路径为：`scripts/thirdparty/autorun/universal-android-ssl-pinning-bypass-2.js`，相同路径下还有bypass webview的js文件，以及老的证书绑定绕过代码(老版本的安卓手机可能会用得到，将头部的Deprecated注释去掉就能使其生效)



## 内置Java类所有函数的hook

这部分代码摘抄自互联网，实现代码在：`scripts/autorun.js`，通过修改其代码实现你想要的功能



有两种方式hook java类

1. 指定需要hook的类全限定名:

```javascript
[
	'java.io.File',
	'java.net.Socket'
].forEach(traceClass);
```

这会hook File和Socket类的所有方法



2. 通过正则表达式hook:

```javascript
Java.enumerateLoadedClasses({
  "onMatch": function(className){
    if (className.match(/^com\.google\./g)) {
      traceClass(className);
    }
  },
  "onComplete": function() {
    send(Date() + " trace classes finished!");
  }
});
```

这会 hook所有以com.google开头的类



## 内置so文件的函数的hook

同样通过修改`scripts/autorun.js`实现你想要的功能



```
[
	'libcommon.so',
].forEach(function (mName) {
```

上面的代码会hook所有libcommon.so里的函数



## 多线程

实现了多线程，因此可以互不影响地同时hook多个设备



## 重定向流量

利用iptables和adb的配合使得Burp Suite能够抓到所有的tcp流量，配合自动证书绑定绕过相当地方便



## 良好的可扩展性

你可以将你的任何hook代码放到scripts目录下就能生效，并且能同时享受到之前提到的功能而不需要另起一个js文件，默认情况下通过修改main.js就好了

