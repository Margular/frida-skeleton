setTimeout(function () {
    Java.perform(function () {
        /*** WebView Hooks ***/
        /* frameworks/base/core/java/android/webkit/WebViewClient.java */
        /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
        var WebViewClient = Java.use("android.webkit.WebViewClient");

        WebViewClient.onReceivedSslError.implementation = function (webView, sslErrorHandler, sslError) {
            send("WebViewClient onReceivedSslError invoke");
            //invoke proceed
            sslErrorHandler.proceed();
        };

        WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String')
            .implementation = function (a, b, c, d) {
            send("WebViewClient onReceivedError invoked(method 1)");
        };

        WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest',
            'android.webkit.WebResourceError').implementation = function () {
            send("WebViewClient onReceivedError invoked(method 2)");
        };
    }, 0);
}, 0);
