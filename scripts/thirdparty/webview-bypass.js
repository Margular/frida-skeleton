setTimeout(function () {
    Java.perform(function () {
        /*** WebView Hooks ***/
        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
        var WebViewClient = Java.use("android.webkit.WebViewClient");

        WebViewClient.onReceivedSslError.implementation = function (webView, sslErrorHandler, sslError) {
            var sendString = Date();
            sendString += " WebViewClient onReceivedSslError invoke";
            send(sendString);
            //invoke proceed
            sslErrorHandler.proceed();
        };

        WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function (a, b, c, d) {
            var sendString = Date();
            sendString += " WebViewClient onReceivedError invoked(method 1)";
            send(sendString);
        };

        WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function () {
            var sendString = Date();
            sendString += " WebViewClient onReceivedError invoked(method 2)";
            send(sendString);
        };
    }, 0);
}, 0);