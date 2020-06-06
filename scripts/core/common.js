var Common = {
    impl: function (method, func) {
        // the function itself rather than overloads
        if ('_o' in method && !('_p' in method)) {
            var overloadCount = method.overloads.length;
            send(JSON.stringify({
                tracing: method.holder.$className + '.' + method.methodName,
                overloaded: overloadCount
            }));
            for (var i = 0; i < overloadCount; i++) {
                Common.impl(method.overloads[i], func);
            }
            return;
        }

        // return if this is not a overload
        if (!('_p' in method)) {
            send('not a overload: ' + JSON.stringify(Common.items(method)));
            return;
        }

        // store method to global, make _method_xxx_ === method, xxx is stored in _method_index_
        // and automatically increments by 1
        // ex: _method_0_ = <method 0>
        //     _method_1_ = <method 1>
        //     _method_2_ = <method 2>
        //     ......
        if (global.hasOwnProperty("_method_index_"))
            global["_method_index_"]++;
        else
            global["_method_index_"] = 0;

        var method_index = global["_method_index_"];
        var method_name = "_method_" + method_index + "_";
        global[method_name] = method;

        // store func to global, same as method
        var func_name = method_name;

        if (func !== undefined) {
            if (global.hasOwnProperty("_func_index_"))
                global["_func_index_"]++;
            else
                global["_func_index_"] = 0;

            var func_index = global["_func_index_"];
            func_name = "_func_" + func_index + "_";
            global[func_name] = func;
        }

        // thanks Zack Argyle
        // https://medium.com/@zackargyle/es6-like-template-strings-in-10-lines-a88caca6f36c
        var impl = '${method_obj}.implementation = function () {\n' +
            '\tvar sendString = "${method_full_name}(";\n' +
            '\tfor (var i = 0; i < arguments.length; i++) {\n' +
            '\t\tvar arg = arguments[i];\n' +
            '\t\tsendString += arg;\n' +
            '\t\tvar prettyArg = Format.pretty(arg);\n' +
            '\t\tif (prettyArg !== arg)\n' +
            '\t\t\tsendString += "|" + prettyArg;\n' +
            '\t\tif (i < arguments.length - 1)\n' +
            '\t\t\tsendString += ", ";\n' +
            '\t}\n' +
            '\tsendString += ")";\n' +
            '\tsend(sendString);\n' +
            '\tvar ret = ${func_obj}.apply(this, arguments);\n' +
            '\tvar prettyRet = Format.pretty(ret);\n' +
            '\tsendString += " => " + ret;\n' +
            '\tif (ret !== prettyRet)\n' +
            '\t\tsendString += "|" + prettyRet;\n' +
            '\tsend(sendString);\n' +
            '\treturn ret;\n' +
            '};';

        impl = impl.replace(/\${(.*?)}/g, function (_, code) {
            var scoped = code.replace(/(["'.\w$]+)/g, function (match) {
                return /["']/.test(match[0]) ? match : 'scope.' + match;
            });

            try {
                return new Function('scope', 'return ' + scoped)({
                    method_obj: method_name,
                    method_full_name: method._p[1].$className + "." + method._p[0],
                    func_obj: func_name
                });
            } catch (e) {
                return '';
            }
        });

        eval(impl);
    },

    printBacktrace: function () {
        var android_util_Log = Java.use('android.util.Log');
        var java_lang_Exception = Java.use('java.lang.Exception');
        // getting stacktrace by throwing an exception
        send(android_util_Log.getStackTraceString(java_lang_Exception.$new()));
    },

    // remove duplicates from array
    uniqBy: function (array, key) {
        var seen = {};
        return array.filter(function (item) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    },

    keys: function (obj) {
        var o = obj;
        var keys = [];

        while (o.__proto__ !== Object.prototype) {
            keys.push(Object.keys(o));
            o = o.__proto__;
        }

        return keys;
    },

    values: function (obj) {
        var o = obj;
        var values = [];
        while (o.__proto__ !== Object.prototype) {
            var keys = Object.keys(o);
            for (var i = 0; i < keys.length; i++) {
                values.push(obj[keys[i]]);
            }
            o = o.__proto__;
        }

        return values;
    },

    items: function (obj) {
        var o = obj;
        var items = {};
        while (o.__proto__ !== Object.prototype) {
            var keys = Object.keys(o);
            for (var i = 0; i < keys.length; i++) {
                var key = keys[i];
                items[key] = obj[key];
            }
            o = o.__proto__;
        }

        return items;
    },

    itemsJson: function (obj) {
        return JSON.stringify(this.items(obj));
    }
};
