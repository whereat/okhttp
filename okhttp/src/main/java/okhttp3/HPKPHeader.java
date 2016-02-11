package okhttp3;

import okhttp3.internal.framed.Header;
import okhttp3.internal.http.HeaderException;
import okio.ByteString;
import org.apache.commons.lang3.math.NumberUtils;
import org.joda.time.DateTime;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Created by rmaalej on 2/5/16.
 */
public class HPKPHeader {
    private static final String PUBLIC_KEY_PINS_REPORT_ONLY = "Public-Key-Pins-Report-Only";
    private static final String PUBLIC_KEY_PINS = "Public-Key-Pins";
    private static final String MAX_AGE_PREFIX = "max-age=";
    private static final String PIN_SHA256_PREFIX = "pin-sha256=\"";
    private static final String REPORT_URI_PREFIX = "report-uri=\"";
    private final String headerName;
    private final int maxAge;
    private final long expirationDateFromEpoch;
    private final boolean subdomainsIncluded;
    private final String reportURI;
    private final Set<String> pins;

    public static HPKPHeader fromHeader(Header header) throws HeaderException {
        if (null == header) {
            throw new HeaderException("Header cannot be null");
        }
        if (null == header.value || header.value.utf8().isEmpty()) {
            throw new HeaderException("Header value cannot be null or empty");
        }
        if (null == header.name || header.name.utf8().isEmpty()) {
            throw new HeaderException("Header name cannot be null or empty");
        }
        if (PUBLIC_KEY_PINS.equals(header.name.utf8())
                && !header.value.utf8().contains(MAX_AGE_PREFIX)) {
            throw new HeaderException("Missing max-age directive (See RFC 7469).");
        }

        boolean includeSubdomains = false;
        String reportURI = null;
        int maxAge = 0;
        long expirationDateFromEpoch = 0;
        Set<String> pins = new LinkedHashSet<>();
        String[] headerPairValuesArray = header.value.utf8().split(";");

        for (String headerPairValue : headerPairValuesArray) {
            String headerPairValueTrimmed = headerPairValue.trim();
            // pin-sha256 directive is case insensitive1
            if (headerPairValueTrimmed.toLowerCase().startsWith(PIN_SHA256_PREFIX)) {
                // -1 to handle "; at the end of the string
                String pinValue = headerPairValueTrimmed.substring(PIN_SHA256_PREFIX.length(),
                        headerPairValueTrimmed.length() - 1);
                if (!isBase64(pinValue)) {
                    throw new HeaderException(
                            String.format("pin %s is not a valid base64 string", pinValue));
                } else {
                    pins.add(pinValue);
                }
            } else if (headerPairValueTrimmed.startsWith(MAX_AGE_PREFIX)) {
                String maxAgeValue = headerPairValueTrimmed.substring(MAX_AGE_PREFIX.length(),
                        headerPairValueTrimmed.length());

                if (!NumberUtils.isNumber(maxAgeValue)) {
                    throw new HeaderException(
                            String.format("max-age %s is not a valid number", maxAgeValue));
                }
                maxAge = Integer.parseInt(maxAgeValue);
                expirationDateFromEpoch = getExpirationDateFromEpoch(maxAge);
            } else if (headerPairValueTrimmed.startsWith(REPORT_URI_PREFIX)) {
                // -1 to handle "; at the end of the string
                reportURI = headerPairValueTrimmed.substring(REPORT_URI_PREFIX.length(),
                        headerPairValueTrimmed.length() - 1);

            } else if (headerPairValueTrimmed.contains("includeSubdomains")) {
                includeSubdomains = true;
            }
        }

        if (pins.isEmpty()) {
            throw new HeaderException("Pins list cannot be empty");
        }

        return new HPKPHeader(header.name.utf8(), maxAge, includeSubdomains,
                reportURI, pins, expirationDateFromEpoch);
    }

    private HPKPHeader(String headerName, int maxAge, boolean subdomainsIncluded,
                       String reportURI, Set<String> pins, long expirationDateFromEpoch) {
        this.headerName = headerName;
        this.maxAge = maxAge;
        this.subdomainsIncluded = subdomainsIncluded;
        this.reportURI = reportURI;
        this.pins = new HashSet<>();
        this.pins.addAll(pins);
        this.expirationDateFromEpoch = expirationDateFromEpoch;
    }

    private HPKPHeader(Builder builder) {
        this.headerName = builder.headerName;
        this.maxAge = builder.maxAge;
        this.subdomainsIncluded = builder.includeSubdomains;
        this.reportURI = builder.reportURI;
        this.pins = builder.pins;
        this.expirationDateFromEpoch = builder.expirationDateFromEpoch;
    }

    public Builder builder() {
        return new Builder(this);
    }

    public long getExpirationDateFromEpoch() { return this.expirationDateFromEpoch; }

    private static long getExpirationDateFromEpoch(int maxAge) {
        return DateTime.now().getMillis() + (maxAge * 1000);
    }

    public int getMaxAge() {
        return maxAge;
    }

    public boolean isSubdomainsIncluded() {
        return subdomainsIncluded;
    }

    public String getReportURI() {
        return reportURI;
    }

    public Set<String> getPins() { return Collections.unmodifiableSet(pins); }

    public String getName() {
        return headerName;
    }

    private static boolean isBase64(String value) {
        ByteString decodedPin = ByteString.decodeBase64(value);
        if (decodedPin == null) {
            return false;
        }
        return true;
    }

    public static final class Builder {
        private Set<String> pins = new HashSet<>();
        private String headerName;
        private int maxAge;
        private long expirationDateFromEpoch;
        private boolean includeSubdomains = false;
        private String reportURI = null;

        public Builder(HPKPHeader hpkHeader) {
            this.headerName = hpkHeader.headerName;
            this.includeSubdomains = hpkHeader.subdomainsIncluded;
            this.maxAge = hpkHeader.maxAge;
            this.pins.addAll(hpkHeader.getPins());
            this.expirationDateFromEpoch = hpkHeader.expirationDateFromEpoch;
            this.reportURI = hpkHeader.reportURI;
        }

        public Builder includeSubdomains(boolean includeSubdomains) {
            this.includeSubdomains = includeSubdomains;
            return this;
        }

        public Builder reportURI(String reportURI) {
            this.reportURI = reportURI;
            return this;
        }

        public Builder maxAge(int value) {
            this.maxAge = value;
            this.expirationDateFromEpoch = getExpirationDateFromEpoch(value);
            return this;
        }

        public Builder pins(Set<String> pins) {
            this.pins.clear();
            this.pins.addAll(pins);
            return this;
        }

        public HPKPHeader build() {
            return new HPKPHeader(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        HPKPHeader that = (HPKPHeader) o;
        if (!headerName.equals(that.headerName)) return false;
        if (maxAge != that.maxAge) return false;
        if (subdomainsIncluded != that.subdomainsIncluded) return false;
        if (reportURI != null ? !reportURI.equals(that.reportURI) : that.reportURI != null) {
            return false;
        }
        return pins.size() == that.pins.size() && pins.containsAll(that.pins);
    }

    @Override
    public int hashCode() {
        int result = maxAge;
        result = 31 * result + headerName.hashCode();
        result = 31 * result + (subdomainsIncluded ? 1 : 0);
        result = 31 * result + (reportURI != null ? reportURI.hashCode() : 0);
        result = 31 * result + pins.hashCode();
        return result;
    }
}
