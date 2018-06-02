/* 
 * Description: Get stack trace of current thread.
 * Author: Margular
 * Date: 2018-06-02
 * Version: 1.0
 */

var Thread = Java.use("java.lang.Thread");

function getStackTrace() {
    var stackTrace = ''
    var stes = Thread.currentThread().getStackTrace();

    for (var i = 0; i < stes.length; i++) {
        stackTrace += stes[i].toString();
        stackTrace += '\n';
    }

    return stackTrace;
}
