/*
 * Description: A js file that defined many useful auto run javascript snippets
 * Author: Margular
 * Date: 2019-12-22
 * Version: 1.1
 */

const Bypass = {
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

        const CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        const FileInputStream = Java.use("java.io.FileInputStream");
	    const BufferedInputStream = Java.use("java.io.BufferedInputStream");
	    const X509Certificate = Java.use("java.security.cert.X509Certificate");
	    const KeyStore = Java.use("java.security.KeyStore");
	    const TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
	    const SSLContext = Java.use("javax.net.ssl.SSLContext");

	    // Load CAs from an InputStream
	    send("[+] Loading our CA...");
	    var cf = CertificateFactory.getInstance("X.509");

	    try {
	    	var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
	    }
	    catch(err) {
	    	send("[o] " + err);
	    }

	    const bufferedInputStream = BufferedInputStream.$new(fileInputStream);
	  	const ca = cf.generateCertificate(bufferedInputStream);
	    bufferedInputStream.close();

		const certInfo = Java.cast(ca, X509Certificate);
	    send("[o] Our CA Info: " + certInfo.getSubjectDN());

	    // Create a KeyStore containing our trusted CAs
	    send("[+] Creating a KeyStore for our CA...");
	    const keyStoreType = KeyStore.getDefaultType();
	    const keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(null, null);
	    keyStore.setCertificateEntry("ca", ca);

	    // Create a TrustManager that trusts the CAs in our KeyStore
	    send("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
	    const tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	    const tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
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
