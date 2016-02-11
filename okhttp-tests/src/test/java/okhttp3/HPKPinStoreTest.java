package okhttp3;

import okhttp3.internal.HeldCertificate;
import okhttp3.internal.framed.Header;
import okhttp3.internal.http.HeaderException;
import okio.ByteString;
import org.junit.Before;
import org.junit.Test;

import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.Assert.fail;

/**
 * Created by rmaalej on 2/5/16.
 */
public class HPKPinStoreTest {
    public static final String PUBLIC_KEY_PINS = "Public-Key-Pins";
    private String pinOne = "cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=";
    private String pinTwo = "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=";
    private HeldCertificate certA1;
    private String certA1Pin;
    private ByteString certA1PinBase64;

    private HeldCertificate certA2;
    private String certA2Pin;
    private ByteString certA2PinBase64;

    @Before
    public void setup() {
        try {
            certA1 = new HeldCertificate.Builder()
                    .serialNumber("100")
                    .build();
            certA1Pin = HPKPinner.pinCertificate(certA1.certificate);
            certA1PinBase64 = ByteString.decodeBase64(certA1Pin);

            certA2 = new HeldCertificate.Builder()
                    .serialNumber("200")
                    .build();
            certA2Pin = HPKPinner.pinCertificate(certA2.certificate);
            certA2PinBase64 = ByteString.decodeBase64(certA2Pin);
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    public void testSuccessfullAddNonExistingHeader() throws HeaderException {
        String hostname = "www.google.com";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        org.junit.Assert.assertTrue(hpkPinStore.getHeaders().size() == 1);
        org.junit.Assert.assertTrue(hpkPinStore.getHeaders().iterator().next().equals(hpkHeader));
    }

    @Test public void testEvictExistingHeaderOnMaxAgeZero() throws HeaderException {
        String hostname = "www.google.com";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        HPKPHeader hpkHeaderExpired = hpkHeader.builder().maxAge(0).build();
        hpkPinStore.add(hostname, hpkHeaderExpired);

        org.junit.Assert.assertTrue(hpkPinStore.getHeaders().size() == 0);
    }

    @Test public void testUpdateHeaderMaxAgeValue() throws HeaderException {
        String hostname = "www.google.com";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        HPKPHeader hpkHeaderUpdated = hpkHeader.builder().maxAge(5000).build();
        hpkPinStore.add(hostname, hpkHeaderUpdated);

        org.junit.Assert.assertTrue(hpkPinStore.getHeaders().size() == 1);
        org.junit.Assert.assertTrue(hpkHeaderUpdated.equals(hpkPinStore.getHeaders().iterator().next()));
    }

    @Test public void testUpdateHeaderSubdomainsIncludedValue() throws HeaderException {
        String hostname = "www.google.com";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        HPKPHeader hpkHeaderUpdated = hpkHeader.builder().includeSubdomains(!hpkHeader.isSubdomainsIncluded()).build();
        hpkPinStore.add(hostname, hpkHeaderUpdated);

        org.junit.Assert.assertTrue(hpkPinStore.getHeaders().size() == 1);
        org.junit.Assert.assertTrue(hpkHeaderUpdated.equals(hpkPinStore.getHeaders().iterator().next()));
    }

    @Test public void testUpdateHeaderReportURIValue() throws HeaderException {
        String hostname = "www.google.com";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        HPKPHeader hpkHeaderUpdated = hpkHeader.builder().reportURI(hpkHeader.getReportURI()+"updated").build();
        hpkPinStore.add(hostname, hpkHeaderUpdated);

        org.junit.Assert.assertTrue(hpkPinStore.getHeaders().size() == 1);
        org.junit.Assert.assertTrue(hpkHeaderUpdated.equals(hpkPinStore.getHeaders().iterator().next()));
    }

    @Test public void testUpdateHeaderReportURIToNonNullValue() throws HeaderException {
        String hostname = "www.google.com";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader.builder().reportURI(null).build());

        HPKPHeader hpkHeaderUpdated = hpkHeader.builder().reportURI(hpkHeader.getReportURI()+"updated").build();
        hpkPinStore.add(hostname, hpkHeaderUpdated);

        org.junit.Assert.assertTrue(hpkPinStore.getHeaders().size() == 1);
        org.junit.Assert.assertTrue(hpkHeaderUpdated.equals(hpkPinStore.getHeaders().iterator().next()));
    }

    @Test public void testUnsuccessfullAddHeaderWithEmptyPinList() throws HeaderException {
        HPKPinStore hpkPinStore = new HPKPinStore();
        String hostname = "www.google.com";

        Header httpHeader = buildHeader(certA1Pin);

        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        HPKPHeader hpkHeaderWithEmpty = hpkHeader.builder().pins(new HashSet()).build();

        try {
            hpkPinStore.add(hostname, hpkHeaderWithEmpty);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {

        }
    }

    @Test public void testUnsuccessfullUpdateOnChangedPinList() throws HeaderException {
        HPKPinStore hpkPinStore = new HPKPinStore();
        String hostname = "www.google.com";

        Header httpHeader = buildHeader(certA1Pin);

        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        hpkPinStore.add(hostname, hpkHeader);

        Set<String> pins = new LinkedHashSet<>();
        pins.add(pinOne);
        pins.add(pinTwo);
        HPKPHeader hpkHeaderUpdated = hpkHeader.builder().pins(pins).build();
        hpkPinStore.add(hostname, hpkHeaderUpdated);

        org.junit.Assert.assertTrue(hpkPinStore.getHeaders().size() == 1);
        org.junit.Assert.assertTrue(hpkHeader.equals(hpkPinStore.getHeaders().iterator().next()));
    }

    @Test public void testSuccessfullFindPinningInformationForDomain() throws HeaderException {
        String hostname = "www.google.com";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);

        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        HPKPHeader result = hpkPinStore.findPinningInformation(hostname);
        org.junit.Assert.assertNotNull(result);
        org.junit.Assert.assertTrue(result.equals(hpkHeader));
    }

    @Test public void testSuccessfullFindPinningInformationForDomainWithoutSubdomainsIncluded() throws HeaderException {
        String hostname = "www.google.com";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader).builder().includeSubdomains(false).build();

        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        HPKPHeader result = hpkPinStore.findPinningInformation(hostname);
        org.junit.Assert.assertNotNull(result);
        org.junit.Assert.assertTrue(result.equals(hpkHeader));
    }

    @Test public void testUnsuccessfullFindPinningInformationForExpired() throws InterruptedException, HeaderException {
        String hostname = "www.google.com";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader).builder().maxAge(1).build();
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);
        Thread.sleep(3000);
        HPKPHeader result = hpkPinStore.findPinningInformation(hostname);
        org.junit.Assert.assertNull(result);
    }

    @Test public void testSuccessfullFindPinningInformationForSubdomainsIfIncluded() throws HeaderException {
        String hostname = "www.example.net";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        HPKPHeader result = hpkPinStore.findPinningInformation("demo.example.net");
        org.junit.Assert.assertNotNull(result);
        org.junit.Assert.assertTrue(result.equals(hpkHeader));
    }

    @Test public void testUnSuccessfullFindPinningInformationForSubdomainsIfNotIncluded() throws HeaderException {
        String hostname = "www.example.net";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader).builder().includeSubdomains(false).build();
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        HPKPHeader result = hpkPinStore.findPinningInformation("demo.example.net");
        org.junit.Assert.assertNull(result);
    }

    @Test public void testSuccessfullFindPinningInformationForLongSubdomains() throws HeaderException {
        String hostname = "www.example.net";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        HPKPinStore hpkPinStore = new HPKPinStore();
        hpkPinStore.add(hostname, hpkHeader);

        HPKPHeader result = hpkPinStore.findPinningInformation("app.demo.example.net");
        org.junit.Assert.assertNotNull(result);
        org.junit.Assert.assertTrue(result.equals(hpkHeader));
    }

    @Test public void testSuccessfulFindPinningInformationForSubdomainIfaParentDomainIsPresentAsWellWithoutSubdomainDirective() throws HeaderException {
        HPKPinStore hpkPinStore = new HPKPinStore();

        String parentDomain = "www.example.net";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader).builder().includeSubdomains(false).build();
        hpkPinStore.add(parentDomain, hpkHeader);

        String subdomain = "demo.example.net";
        Header httpHeaderSubdomain = buildHeader(certA2Pin);
        HPKPHeader hpkHeaderSubdomain = HPKPHeader.fromHeader(httpHeaderSubdomain).builder().includeSubdomains(false).build();
        hpkPinStore.add(subdomain, hpkHeaderSubdomain);

        HPKPHeader result = hpkPinStore.findPinningInformation(subdomain);
        org.junit.Assert.assertNotNull(result);
        org.junit.Assert.assertTrue(result.equals(hpkHeaderSubdomain));
    }

    @Test public void testSuccessfulFindPinningInformationForSubdomainIfaParentDomainIsPresentAsWellWithSubdomainDirective() throws HeaderException {
        HPKPinStore hpkPinStore = new HPKPinStore();

        String parentDomain = "www.example.net";
        Header httpHeader = buildHeader(certA1Pin);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(httpHeader);
        hpkPinStore.add(parentDomain, hpkHeader);

        String subdomain = "demo.example.net";
        Header httpHeaderSubdomain = buildHeader(certA2Pin);
        HPKPHeader hpkHeaderSubdomain = HPKPHeader.fromHeader(httpHeaderSubdomain).builder().includeSubdomains(false).build();
        hpkPinStore.add(subdomain, hpkHeaderSubdomain);

        HPKPHeader result = hpkPinStore.findPinningInformation(subdomain);
        org.junit.Assert.assertNotNull(result);
        org.junit.Assert.assertTrue(result.equals(hpkHeaderSubdomain));
    }

    private Header buildHeader(String pin) {
        String headerString = "pin-sha256=\"%s\"; max-age=5184000; includeSubdomains; report-uri=\"https://www.example.net/hpkp-report\"";
        return new Header(PUBLIC_KEY_PINS, String.format(headerString, pin));
    }
}
