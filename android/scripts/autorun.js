/*
 * Description: A js file that defined many useful auto run javascript snippets
 * Author: Margular
 * Date: 2019-08-21
 * Version: 1.0
 */


setTimeout(function (){Java.perform(function() {
    /*****************************Trace Java Classes****************************/
    /* METHOD 1: specify several classes to trace */
    [
//        'java.io.File',
//        'java.net.Socket'
    ].forEach(traceClass);

    /* METHOD 2: trace using regular expression */
    Java.enumerateLoadedClasses({
        "onMatch": function(className){
            if (className.match(/^$/g)) {
                traceClass(className);
            }
        },
        "onComplete": function() {
            send(Date() + " trace classes finished!");
        }
    });
    /*****************************Trace Java Classes End*************************/

    /*****************************Trace JNI*************************/
    [
//        'libxxx.so',
    ].forEach(function (mName) {
        Module.enumerateExports(mName, {
            onMatch: function(e) {
                if(e.type == 'function') {
                    send(Date() + " Intercepting jni function: " + e.name + "(" + e.address + "|" +
                        e.address.sub(Module.findBaseAddress(mName)) + ")");
                    try {
                        Interceptor.attach(e.address, {
                            onEnter: function(args) {
                                this.sendString = Date() + " " + e.name + "(addr: " + e.address + "|" +
                                    e.address.sub(Module.findBaseAddress(mName)) + ", args: {";

                                var i = 0;
                                while (1) {
                                    try {
                                        this.sendString += args[i].readUtf8String();
                                    } catch(error) {
                                        // can not convert to string
                                        this.sendString += " ";
                                    } finally {
                                        if (i) {
                                            this.sendString += ", ";
                                        }
                                    }

                                    i++;
                                    if (i > 20) break;
                                }

                                this.sendString += "}) called from: { " +
                                    Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join(', ');
                            },
                            onLeave: function(retVal){
                                this.sendString += " } -> " + retVal;
                                send(this.sendString);
                            }
                        });
                    } catch (error) {
                        send(Date() + " " + error);
                    }
                }
            },
            onComplete: function() {}
        });
    });
    /*****************************Trace JNI End*************************/
})});