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
                // ret method(args)
                describe.methods.push(overload.returnType.className + ' ' + overload.methodName + '('
                    + overload.argumentTypes.map(function (argumentType) {return argumentType.className;}).join()
                    + ')');
            });
        });

        // search fields
        Common.propertyNames(obj).filter(function (propertyName) {
            var property = obj[propertyName];
            return typeof (property) !== 'string' && 'fieldType' in property;
        }).forEach(function (fieldName) {
            var field = obj[fieldName];
            // type name = value
            describe.fields.push(field.fieldReturnType.className + ' ' + fieldName + ' = ' + field.value);
        });

        return describe;
    }
};
