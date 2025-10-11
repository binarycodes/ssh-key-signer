import java.net.URI;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import java.net.HttpURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HealthCheck {
    public static void main(String[] args) throws java.lang.Throwable {
        final URL url = new URI(args[0]).toURL();
        int exitCode = switch(url.getProtocol()) {
            case "https" -> forHttps(url);
            case "http" -> forHttp(url);
            default -> 2;
        };
        System.exit(exitCode);
    }

    private static int forHttp(URL url) throws java.lang.Throwable {
        final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        final int exitCode = java.net.HttpURLConnection.HTTP_OK == connection.getResponseCode() ? 0 : 1;
        return exitCode;
    }

    private static int forHttps(URL url) throws java.lang.Throwable {
        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, bypassCertificate(), new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // Create all-trusting host name verifier
        HostnameVerifier allHostsValid = (hostname, session) -> true;

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

        final HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        final int exitCode = java.net.HttpURLConnection.HTTP_OK == connection.getResponseCode() ? 0 : 1;
        return exitCode;
    }


    private static TrustManager[] bypassCertificate() {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };
        return trustAllCerts;
    }
}
