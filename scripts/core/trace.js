// thanks iddoeldor: https://github.com/iddoeldor/frida-snippets

var Trace = {
    javaClassMethod: function (targetClassMethod) {
        var delim = targetClassMethod.lastIndexOf('.');
        if (delim === -1)
            return;

        var targetClass = targetClassMethod.slice(0, delim);
        var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

        var hook = Java.use(targetClass);
        try {
            var overloadCount = hook[targetMethod].overloads.length;
        } catch (e) {
            // cannot read property 'overloads' of undefined
            send(e.message)
        }

        send(JSON.stringify({tracing: targetClassMethod, overloaded: overloadCount}));

        for (var i = 0; i < overloadCount; i++) {
            Common.impl(hook[targetMethod].overloads[i]);
        }

        return overloadCount;
    },

    javaClassName: function (targetClass) {
        try {
            var hook = Java.use(targetClass);
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

        var countJson = {class: targetClass, methodCount: parsedMethods.length, overloadCount: 0};

        Common.uniqBy(parsedMethods, JSON.stringify).forEach(function (targetMethod) {
            countJson.overloadCount += Trace.javaClassMethod(targetClass + '.' + targetMethod);
        });

        send(JSON.stringify(countJson));

        return countJson;
    },

    javaClassNames: function (classes) {
        classes.forEach(this.javaClassName);
    },

    javaClassByRegex: function (regexp) {
        var info = {regexp: regexp.toString(), classCount: 0, methodCount: 0, overloadCount: 0};

        Java.enumerateLoadedClasses({
            "onMatch": function (className) {
                if (className.match(regexp)) {
                    var countJson = Trace.javaClassName(className);
                    info.classCount++;
                    info.methodCount += countJson.methodCount;
                    info.overloadCount += countJson.overloadCount;
                }
            },
            "onComplete": function () {
            }
        });

        send(JSON.stringify(info));
    },

    jniName: function (mName) {
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
                                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                                        .map(DebugSymbol.fromAddress).join(', ');
                            },
                            onLeave: function (retVal) {
                                this.sendString += " } -> " + retVal;
                                send(this.sendString);
                            }
                        });
                    } catch (error) {
                        console.error(error);
                    }
                }
            },
            onComplete: function () {
            }
        });
    },

    jniNames: function (mNames) {
        mNames.forEach(this.jniName);
    },

    propertyGet: function () {
        Interceptor.attach(Module.findExportByName(null, '__system_property_get'), {
            onEnter: function (args) {
                this._name = args[0].readCString();
                this._value = args[1];
            },
            onLeave: function (retval) {
                send(JSON.stringify({
                    result_length: retval,
                    name: this._name,
                    val: this._value.readCString()
                }));
            }
        });
    },

    hiddenNativeMethods: function () {
        var pSize = Process.pointerSize;
        var env = Java.vm.getEnv();
        // search "215" @ https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html
        var RegisterNatives = 215, FindClassIndex = 6;
        var jclassAddress2NameMap = {};

        function getNativeAddress(idx) {
            return env.handle.readPointer().add(idx * pSize).readPointer();
        }

        // intercepting FindClass to populate Map<address, jclass>
        Interceptor.attach(getNativeAddress(FindClassIndex), {
            onEnter: function (args) {
                jclassAddress2NameMap[args[0]] = args[1].readCString();
            }
        });

        // RegisterNative(jClass*, .., JNINativeMethod *methods[nMethods], uint nMethods)
        // https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h#977
        Interceptor.attach(getNativeAddress(RegisterNatives), {
            onEnter: function (args) {
                for (var i = 0, nMethods = parseInt(args[3]); i < nMethods; i++) {
                    /*
                      https://android.googlesource.com/platform/libnativehelper/+/master/include_jni/jni.h#129
                      typedef struct {
                         const char* name;
                         const char* signature;
                         void* fnPtr;
                      } JNINativeMethod;
                    */
                    var structSize = pSize * 3; // = sizeof(JNINativeMethod)
                    var methodsPtr = ptr(args[2]);
                    var signature = methodsPtr.add(i * structSize + pSize).readPointer();
                    var fnPtr = methodsPtr.add(i * structSize + (pSize * 2)).readPointer(); // void* fnPtr
                    var jClass = jclassAddress2NameMap[args[0]].split('/');
                    send(JSON.stringify({
                        // https://www.frida.re/docs/javascript-api/#debugsymbol
                        module: DebugSymbol.fromAddress(fnPtr)['moduleName'],
                        package: jClass.slice(0, -1).join('.'),
                        class: jClass[jClass.length - 1],
                        method: methodsPtr.readPointer().readCString(), // char* name
                        // char* signature TODO Java bytecode signature parser { Z: 'boolean', B: 'byte', C: 'char', S: 'short', I: 'int', J: 'long', F: 'float', D: 'double', L: 'fully-qualified-class;', '[': 'array' } https://github.com/skylot/jadx/blob/master/jadx-core/src/main/java/jadx/core/dex/nodes/parser/SignatureParser.java
                        signature: signature.readCString(),
                        address: fnPtr
                    }));
                }
            }
        });
    }
};
