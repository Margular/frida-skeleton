/*
 * Description: Common functions for common usage.
 * Author: Margular
 * Date: 2019-08-21
 * Version: 1.0
 */

var Class = Java.use("java.lang.Class");
var StringBuilder = Java.use("java.lang.StringBuilder");

/* return values of declared fields of an object
 * o: object to extract
 * parent: a boolean variable that indicates whether to extract parent fields of the object
 */
function extractDeclaredFields(o) {
    var currentClass = Java.cast(o.getClass(), Class);
    var sb = StringBuilder.$new();

    while (currentClass.__proto__.hasOwnProperty('getName')) {
        sb.append(currentClass.getName()).append("=====");
        currentClass.getDeclaredFields().forEach(function(field) {
            field.setAccessible(true);
            sb.append(field.getName()).append(": ").append(field.get(o)).append('---');
        });
        currentClass = currentClass.getSuperclass();
    }

    return sb.toString();
}