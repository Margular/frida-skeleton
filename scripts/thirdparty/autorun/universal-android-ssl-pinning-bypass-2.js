setTimeout(function(){
    Java.perform(function() {
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');

        ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
            send('Bypassing SSL Pinning');
            return array_list.$new();
        }
    },0);
},0);
