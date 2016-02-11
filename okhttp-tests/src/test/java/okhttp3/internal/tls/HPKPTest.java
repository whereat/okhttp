package okhttp3.internal.tls;

import okhttp3.*;
import okhttp3.internal.HeldCertificate;
import okhttp3.internal.SslContextBuilder;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.List;

import static okhttp3.TestUtil.defaultClient;
import static org.junit.Assert.fail;

/**
 * Created by rmaalej on 2/9/16.
 */
public class HPKPTest {
    @Rule public final MockWebServer server = new MockWebServer();
    private OkHttpClient client;
    private SSLContext sslContext;
    private HeldCertificate certA1;
    private String certA1Pin;

    @Before
    public void setup() throws GeneralSecurityException {
        client = defaultClient();
        sslContext = SslContextBuilder.localhost();
        certA1 = new HeldCertificate.Builder()
                .serialNumber("100")
                .build();
        certA1Pin = HPKPinner.pinCertificate(certA1.certificate);
    }

    @Test public void testIgnorePinningOnFirstUseOnNonSecureConnection() throws Exception {
        String pin = "qNS1RuLIIxRR4bdjfPSP9vBr9HU8u01IoWzrbpHOMuI=";

        HttpUrl urlWithIpAddress = url(server, "/path/foo");
        server.enqueue(new MockResponse().addHeader("Public-Key-Pins: " +
                "pin-sha256=\""+pin+"\"; " +
                "max-age=300; " +
                "includeSubDomains "));
        get(urlWithIpAddress, client);

        HPKPHeader hpkpHeader = client.hpkPinStore().findPinningInformation(server.getHostName());

        Assert.assertNull(hpkpHeader);
    }

    @Test public void testSuccessfullPinningOnFirstUseOnSecureConnection() throws Exception {
        enableTlsForTrustedServer();

        List<Certificate> serverCertificates = getServerCertificates(server, client);
        String pin = HPKPinner.pinCertificate(serverCertificates.get(0));

        HttpUrl url = url(server, "/path/foo");
        server.enqueue(new MockResponse().addHeader("Public-Key-Pins: " +
                "pin-sha256=\"" + pin + "\"; " +
                "max-age=300; " +
                "includeSubDomains "));
        get(url, client);

        HPKPHeader hpkpHeader = client.hpkPinStore().findPinningInformation(server.getHostName());

        Assert.assertNotNull(hpkpHeader);
        Assert.assertTrue(hpkpHeader.getPins().contains(pin));
    }

    @Test public void testAbortConnectionOnManInTheMiddleAttackWithoutHPKPHeader() throws Exception {
        enableTlsForTrustedServer();

        List<Certificate> serverCertificates = getServerCertificates(server, client);
        String pin = HPKPinner.pinCertificate(serverCertificates.get(0));

        HttpUrl url = url(server, "/path/foo");
        server.enqueue(new MockResponse().addHeader("Public-Key-Pins: " +
                "pin-sha256=\"" + pin + "\"; " +
                "max-age=300; " +
                "includeSubDomains "));
        get(url, client);

        HttpUrl url2 = url(server, "/path/foo/2");
        server.enqueue(new MockResponse());
        try {
            get(url2, client);
            fail("An exception is expected here");
        } catch (SSLPeerUnverifiedException expected) {

        }
    }

    private void enableTlsForTrustedServer() {
        client = client.newBuilder().sslSocketFactory(sslContext.getSocketFactory())
                .hostnameVerifier(new RecordingHostnameVerifier()).build();
        server.useHttps(sslContext.getSocketFactory(), false);
    }

    private HttpUrl url(MockWebServer server, String path) throws Exception {
        return server.url(path).newBuilder()
                .host(server.getHostName())
                .build();
    }

    private void get(HttpUrl url, OkHttpClient client) throws Exception {
        Call call = client.newCall(new Request.Builder().url(url).build());
        Response response = call.execute();
        response.body().close();
    }

    private List<Certificate> getServerCertificates(MockWebServer server, OkHttpClient client) throws Exception {
        List<Certificate> serverCertificates = null;
        HttpUrl urlWithIpAddress = url(server, "/");

        server.enqueue(new MockResponse());

        Call call = client.newCall(new Request.Builder().url(urlWithIpAddress).build());
        Response response = call.execute();
        serverCertificates = response.handshake().peerCertificates();
        response.body().close();

        return serverCertificates;
    }
}
