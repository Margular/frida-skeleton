var Jav = {
    describeObject: function (obj) {
        if (typeof(obj) !== 'object' || !('class' in obj)) {
            return obj;
        }

        var describe = {class: obj.class.getName(), methods: [], fields: []};

        // search methods
        Common.propertyNames(obj).map(function (propertyName) {
            return obj[propertyName];
        }).filter(function (property) {
            return typeof (property) !== 'string' && 'overloads' in property;
        }).forEach(function (method) {
            method.overloads.forEach(function (overload) {
                describe.methods.push('ret method(args)'
                    .replace(/method/, overload.methodName)
                    .replace(/ret/, overload.returnType.className)
                    .replace(/args/, overload.argumentTypes.map(function (argumentType) {
                        return argumentType.className;
                    }).join())
                );
            });
        });

        // search fields
        Common.propertyNames(obj).filter(function (propertyName) {
            var property = obj[propertyName];
            return typeof (property) !== 'string' && 'fieldType' in property;
        }).forEach(function (fieldName) {
            var field = obj[fieldName];
            describe.fields.push('type name = value'
                .replace(/type/, field.fieldReturnType.className)
                .replace(/name/, fieldName)
                .replace(/value/, field.value)
            );
        });

        return describe;
    }
};
