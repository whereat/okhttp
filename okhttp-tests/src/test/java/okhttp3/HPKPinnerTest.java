package okhttp3;

import okhttp3.internal.HeldCertificate;
import okhttp3.internal.framed.Header;
import okhttp3.internal.http.HeaderException;
import okio.ByteString;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.GeneralSecurityException;

import static org.junit.Assert.fail;

/**
 * Created by rmaalej on 2/5/16.
 */
public class HPKPinnerTest {
    public static final String PUBLIC_KEY_PINS_HEADER_NAME = "Public-Key-Pins";
    String headerString = "pin-sha256=\"%s\"; max-age=5184; includeSubdomains; report-uri=\"https://www.example.net/hpkp-report\"";
    private HPKPinner hpkPinner;

    static HeldCertificate certA1;
    static String certA1Pin;
    static ByteString certA1PinBase64;
    static HeldCertificate certB1;
    static String certB1Pin;
    static ByteString certB1PinBase64;

    static HeldCertificate certC1;
    static String certC1Pin;

    @Before
    public void setup() {
        hpkPinner = new HPKPinner(new HPKPinStore());

        try {
            certA1 = new HeldCertificate.Builder()
                    .serialNumber("100")
                    .build();
            certA1Pin = HPKPinner.pinCertificate(certA1.certificate);
            certA1PinBase64 = ByteString.decodeBase64(certA1Pin);

            certB1 = new HeldCertificate.Builder()
                    .serialNumber("200")
                    .build();
            certB1Pin = HPKPinner.pinCertificate(certB1.certificate);
            certB1PinBase64 = ByteString.decodeBase64(certB1Pin);

            certC1 = new HeldCertificate.Builder()
                    .serialNumber("300")
                    .build();
            certC1Pin = HPKPinner.pinCertificate(certC1.certificate);
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    @Test public void testSuccessfullPinningForKnownDomain() throws HeaderException {
        String hostname = "www.example.net";
        Response response = new Response.Builder()
                .request(new Request.Builder().url("http://www.example.net").build())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .addHeader(PUBLIC_KEY_PINS_HEADER_NAME, buildHeader(certA1Pin)).build();

        try {
            hpkPinner.pinHost(hostname, response, certA1.certificate);
        } catch (SSLPeerUnverifiedException notExpected) {
            fail("Exception should not be raised here");
        }
    }

    @Test public void testUnsuccessfullPinningForUntrustedPins() throws HeaderException {
        String hostname = "demo.example.net";

        Response response = new Response.Builder()
                .request(new Request.Builder().url("http://demo.example.net").build())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .addHeader(PUBLIC_KEY_PINS_HEADER_NAME, buildHeader(certA1Pin)).build();
        try {
            hpkPinner.pinHost(hostname, response, certB1.certificate);
            fail("Should have thrown an exception here");
        } catch (SSLPeerUnverifiedException notExpected) {}
    }

    @Test public void testUnsuccessfullPinningForUntrustedHostPretendingToBeAKnownHost() {
        String hostname = "demo.example.net";

        Response response = new Response.Builder()
                .request(new Request.Builder().url("http://demo.example.net").build())
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .addHeader(PUBLIC_KEY_PINS_HEADER_NAME, buildHeader(certA1Pin)).build();

        Response untrustedResponse = new Response.Builder()
                .request(new Request.Builder().url("http://demo.example.net").build())
                .protocol(Protocol.HTTP_1_1)
                .code(200).build();
        try {
            hpkPinner.pinHost(hostname, response, certA1.certificate);
            hpkPinner.pinHost(hostname, untrustedResponse, certB1.certificate);
            fail("Should have thrown an exception here");
        } catch (SSLPeerUnverifiedException notExpected) {}
    }

    private String buildHeader(String pin) {
        return String.format(headerString, pin);
    }
}
