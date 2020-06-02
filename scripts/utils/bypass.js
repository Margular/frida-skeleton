var Bypass = {
    universal : function () {
		var array_list = Java.use("java.util.ArrayList");
		var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');

		ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
            send('Bypassing SSL Pinning');
            return array_list.$new();
        };
    },

    /**
     * Android SSL Re-pinning frida script v0.2 030417-pier
     * https://techblog.mediaservice.net/2017/07/universal-android-ssl-pinning-bypass-with-frida/
     * */
    byCert : function () {
	    send("[.] Cert Pinning Bypass/Re-Pinning");

        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        var FileInputStream = Java.use("java.io.FileInputStream");
	    var BufferedInputStream = Java.use("java.io.BufferedInputStream");
	    var X509Certificate = Java.use("java.security.cert.X509Certificate");
	    var KeyStore = Java.use("java.security.KeyStore");
	    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
	    var SSLContext = Java.use("javax.net.ssl.SSLContext");

	    // Load CAs from an InputStream
	    send("[+] Loading our CA...");
		var cf = CertificateFactory.getInstance("X.509");

		try {
	    	var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
	    }
	    catch(err) {
	    	send("[o] " + err);
	    }

	    var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
	  	var ca = cf.generateCertificate(bufferedInputStream);
	    bufferedInputStream.close();

		var certInfo = Java.cast(ca, X509Certificate);
	    send("[o] Our CA Info: " + certInfo.getSubjectDN());

	    // Create a KeyStore containing our trusted CAs
	    send("[+] Creating a KeyStore for our CA...");
	    var keyStoreType = KeyStore.getDefaultType();
	    var keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(null, null);
	    keyStore.setCertificateEntry("ca", ca);

	    // Create a TrustManager that trusts the CAs in our KeyStore
	    send("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
	    var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	    var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
	    tmf.init(keyStore);
	    send("[+] Our TrustManager is ready...");

	    send("[+] Hijacking SSLContext methods now...");
	    send("[-] Waiting for the app to invoke SSLContext.init()...");

	   	SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;",
			"java.security.SecureRandom").implementation = function(a,b,c) {
	   		send("[o] App invoked javax.net.ssl.SSLContext.init...");
	   		SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;",
				"java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
	   		send("[+] SSLContext initialized with our custom TrustManager!");
	   	};
    }
};
