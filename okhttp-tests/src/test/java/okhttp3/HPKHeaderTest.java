package okhttp3;

import okhttp3.internal.framed.Header;
import okhttp3.internal.http.HeaderException;
import org.joda.time.DateTime;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Created by rmaalej on 2/5/16.
 */
public class HPKHeaderTest {
    public static final String PUBLIC_KEY_PINS = "Public-Key-Pins";
    public static final int MAX_AGE = 5184000;
    public static final int ONE_SECOND_MILLIS = 1000;
    private String pinOne = "cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=";
    private String pinTwo = "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=";

    private int maxAge = MAX_AGE;
    private String reportURI = "https://www.example.net/hpkp-report";
    private boolean isSubdomainsIncluded = true;

    private String fullHPKPHeader = "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; max-age=5184000; includeSubdomains; report-uri=\"https://www.example.net/hpkp-report\"";
    private String shortHPKPHeader = "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; max-age=5184000";
    private String emptyPinsHPKPHeader = "max-age=5184000";

    @Test public void testSuccessfullCreationFromAllValues() throws HeaderException {
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS, getFullHPKPHeader()));
        assertTrue(PUBLIC_KEY_PINS.equals(hpkHeader.getName()));
        assertTrue(hpkHeader.getMaxAge() == MAX_AGE);
        assertTrue(hpkHeader.isSubdomainsIncluded());
        assertTrue("https://www.example.net/hpkp-report".equals(hpkHeader.getReportURI()));
        assertTrue(hpkHeader.getPins().size() == 2);
        assertTrue(hpkHeader.getPins().contains(pinOne));
        assertTrue(hpkHeader.getPins().contains(pinTwo));
    }

    @Test public void testSuccessfullCreationFromMandatoryValues() throws HeaderException {
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS, getShortHPKPHeader()));
        assertTrue(PUBLIC_KEY_PINS.equals(hpkHeader.getName()));
        assertTrue(hpkHeader.getMaxAge() == MAX_AGE);
        assertFalse(hpkHeader.isSubdomainsIncluded());
        assertNull(hpkHeader.getReportURI());
        assertTrue(hpkHeader.getPins().size() == 2);
        assertTrue(hpkHeader.getPins().contains(pinOne));
        assertTrue(hpkHeader.getPins().contains(pinTwo));
    }

    @Test public void testSuccessfullCreationWithExpirationDate() throws HeaderException {
        long nowInMillis = DateTime.now().getMillis() +  (MAX_AGE * ONE_SECOND_MILLIS);
        HPKPHeader hpkHeader = HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS, getShortHPKPHeader()));
        long expirationDateUpperLimitInMillis = DateTime.now().getMillis() +  (MAX_AGE * ONE_SECOND_MILLIS);
        assertTrue(PUBLIC_KEY_PINS.equals(hpkHeader.getName()));
        assertTrue(hpkHeader.getMaxAge() == MAX_AGE);
        assertFalse(hpkHeader.isSubdomainsIncluded());
        assertNull(hpkHeader.getReportURI());
        assertTrue(hpkHeader.getPins().size() == 2);
        assertTrue(hpkHeader.getPins().contains(pinOne));
        assertTrue(hpkHeader.getPins().contains(pinTwo));
        // It's an interval since there are some processing that has to be done to create the header
        assertTrue(hpkHeader.getExpirationDateFromEpoch() >= nowInMillis);
        assertTrue(hpkHeader.getExpirationDateFromEpoch() <= expirationDateUpperLimitInMillis);
    }

    @Test public void SuccessfullCreationCaseInsensitiveForPinDirective() throws HeaderException {
        String shortHeader = getShortHPKPHeader().replace("pin", "PiN");
        HPKPHeader hpkpHeader = HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS, shortHeader));
        assertTrue(PUBLIC_KEY_PINS.equals(hpkpHeader.getName()));
        assertTrue(hpkpHeader.getMaxAge() == MAX_AGE);
        assertFalse(hpkpHeader.isSubdomainsIncluded());
        assertNull(hpkpHeader.getReportURI());
        assertTrue(hpkpHeader.getPins().size() == 2);
        assertTrue(hpkpHeader.getPins().contains(pinOne));
        assertTrue(hpkpHeader.getPins().contains(pinTwo));

    }

    @Test public void testUnsuccessfulCreationFromNullHeader() {
        try {
            HPKPHeader.fromHeader(null);
            fail("Should have thrown IllegalArgumentException");
        } catch (HeaderException expected) {
        }
    }

    @Test public void testUnsuccessfulCreationFromEmptyHeader() {
        try {
            HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS, ""));
            fail("Should have thrown IllegalArgumentException");
        } catch (HeaderException expected) {
        }
    }

    @Test public void testUnsuccessfulCreationFromInvalidHeader() {
        try {
            HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS, "invalid header"));
            fail("Should have thrown IllegalArgumentException");
        } catch (HeaderException expected) {
        }
    }

    @Test public void testUnsuccessfulCreationFromEmptyPinList() {
        try {
            HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS, emptyPinsHPKPHeader));
            fail("Should have thrown IllegalArgumentException");
        } catch (HeaderException expected) {
        }
    }

    @Test public void testGetFullHPKPHeader() {
        assertTrue(fullHPKPHeader.equals(getFullHPKPHeader()));
    }

    @Test public void testGetShortHPKPHeader() {
        assertTrue(shortHPKPHeader.equals(getShortHPKPHeader()));
    }

    @Test public void testHeaderEquality() throws HeaderException {
        HPKPHeader httpHeader1 = HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS, "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; max-age=5184000; includeSubdomains; report-uri=\"https://www.example.net/hpkp-report\""));
        HPKPHeader httpHeader2 = HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS, "pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; max-age=5184000; includeSubdomains; report-uri=\"https://www.example.net/hpkp-report\""));

        assertTrue(httpHeader1.equals(httpHeader2));
        assertTrue(httpHeader1.hashCode() == httpHeader2.hashCode());
    }

    private String getFullHPKPHeader() {
        StringBuilder sb = new StringBuilder(getShortHPKPHeader());
        sb.append("; ").append(isSubdomainsIncluded ? "includeSubdomains;" : "");
        sb.append(" ").append("report-uri=\"").append(reportURI).append("\"");
        return sb.toString();
    }

    private String getShortHPKPHeader() {
        StringBuilder sb = new StringBuilder();
        sb.append("pin-sha256=\"").append(pinOne).append("\";")
        .append(" ").append("pin-sha256=\"").append(pinTwo).append("\";")
        .append(" ").append("max-age=").append(maxAge);
        return sb.toString();
    }
}
