/*
 * Description: A js file that defined many useful auto run javascript snippets
 * Author: Margular
 * Date: 2019-12-22
 * Version: 1.1
 */

const Trace = {
    method : function (targetClassMethod) {
        var delim = targetClassMethod.lastIndexOf('.');
        if (delim === -1)
            return;

        var targetClass = targetClassMethod.slice(0, delim);
        var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

        var hook = Java.use(targetClass);
        var overloadCount = hook[targetMethod].overloads.length;

        LOG({ tracing: targetClassMethod, overloaded: overloadCount });

        for (var i = 0; i < overloadCount; i++) {
            hook[targetMethod].overloads[i].implementation = function () {
                var log = { '#': targetClassMethod, args: [] };

                for (var j = 0; j < arguments.length; j++) {
                    var arg = arguments[j];
                    // quick&dirty fix for java.io.StringWriter char[].toString() impl because frida prints [object Object]
                    if (j === 0 && arguments[j]) {
                        if (arguments[j].toString() === '[object Object]') {
                            var s = [];
                            for (var k = 0, l = arguments[j].length; k < l; k++) {
                                s.push(arguments[j][k]);
                            }
                            arg = s.join('');
                        }
                    }
                    //log.args.push({ i: j, o: arg, s: arg ? arg.toString(): 'null'});
                    log.args.push(arg ? arg.toString(): 'null');
                }

                var retval;
                try {
                    retval = this[targetMethod].apply(this, arguments); // might crash (Frida bug?)
                    log.returns = { val: retval, str: retval ? retval.toString() : null };
                } catch (e) {
                    console.error(e);
                }
                LOG(log);
                return retval;
            }
        }
    },

    class : function (targetClass) {
        var hook;
        try {
            hook = Java.use(targetClass);
        } catch (e) {
            console.error("trace class failed", e);
            return;
        }

        var methods = hook.class.getDeclaredMethods();
        hook.$dispose();

        var parsedMethods = [];
        methods.forEach(function (method) {
            var methodStr = method.toString();
            var methodReplace = methodStr.replace(targetClass + ".", "TOKEN")
                .match(/\sTOKEN(.*)\(/)[1];
             parsedMethods.push(methodReplace);
        });

        uniqBy(parsedMethods, JSON.stringify).forEach(function (targetMethod) {
            traceMethod(targetClass + '.' + targetMethod);
        });
    },

    classes: function (classes) {
        classes.forEach(traceClass);
    },

    byRegexp: function (regexp) {
        Java.enumerateLoadedClasses({
            "onMatch": function (className) {
                if (className.match(regexp)) {
                    traceClass(className);
                }
            },
            "onComplete": function () {
            }
        });
    },

    jni: function (mNames) {
        mNames.forEach(function (mName) {
            Module.enumerateExports(mName, {
                onMatch: function (e) {
                    if (e.type === 'function') {
                        send("Intercepting jni function: " + e.name + "(" + e.address + "|" +
                            e.address.sub(Module.findBaseAddress(mName)) + ")");
                        try {
                            Interceptor.attach(e.address, {
                                onEnter: function (args) {
                                    this.sendString = e.name + "(addr: " + e.address + "|" +
                                        e.address.sub(Module.findBaseAddress(mName)) + ", args: {";

                                    var i = 0;
                                    while (1) {
                                        try {
                                            this.sendString += args[i].readUtf8String();
                                        } catch (error) {
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
                                        Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                                            .join(', ');
                                },
                                onLeave: function (retVal) {
                                    this.sendString += " } -> " + retVal;
                                    send(this.sendString);
                                }
                            });
                        } catch (error) {
                            send(error);
                        }
                    }
                },
                onComplete: function () {
                }
            });
        });
    }
};
