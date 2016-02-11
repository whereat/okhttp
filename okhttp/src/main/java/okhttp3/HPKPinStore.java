package okhttp3;

import org.joda.time.DateTime;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by rmaalej on 2/5/16.
 */
public final class HPKPinStore {

    private final Map<String, HPKPHeader> hostHeaders = new ConcurrentHashMap<>();

    public HPKPinStore() { }

    public void add(String hostname, HPKPHeader hpkHeader) {
        if (null == hpkHeader) {
            throw new IllegalArgumentException("HPKPHeader cannot be null");
        }
        if (hpkHeader.getPins().isEmpty()) {
            throw new IllegalArgumentException("HPKPHeader pins list cannot be empty");
        }

        String sanitizedHostname = sanitizeHostname(hostname);

        if (hpkHeader.getMaxAge() == 0) {
            hostHeaders.remove(sanitizedHostname);
            return;
        }

        HPKPHeader oldValue = hostHeaders.put(sanitizedHostname, hpkHeader);
        if (null != oldValue) {
            // revert only if both headers don't contain the same list of pins
            if (shouldRevert(oldValue, hpkHeader)) {
                hostHeaders.put(sanitizedHostname, oldValue);
            }
        }
    }

    private boolean shouldRevert(HPKPHeader oldHeader, HPKPHeader newHeader) {
        if (oldHeader.getMaxAge() != newHeader.getMaxAge()
                && !arePinsDifferent(oldHeader, newHeader)) {
            return false;
        }
        if (oldHeader.isSubdomainsIncluded() != newHeader.isSubdomainsIncluded()
                && !arePinsDifferent(oldHeader, newHeader)) {
            return false;
        }
        if (!equalsString(oldHeader.getReportURI(), newHeader.getReportURI())
                && !arePinsDifferent(oldHeader, newHeader)) {
            return false;
        }
        return true;
    }

    private boolean arePinsDifferent(HPKPHeader oldHeader, HPKPHeader newHeader) {
        if (oldHeader.getPins().size() == newHeader.getPins().size()
                && oldHeader.getPins().containsAll(newHeader.getPins())) {
            return false;
        }
        return true;
    }

    public HPKPHeader findPinningInformation(String hostname) {
        long nowInMillis = DateTime.now().getMillis();
        HPKPHeader result = null;
        int offset = 0;
        String[] hostnameSegments = sanitizeHostname(hostname).split("\\.");

        while (null == result && offset < hostnameSegments.length) {
            String hostnameToSearch = getHostnameToSearch(hostnameSegments, offset);
            result = hostHeaders.get(hostnameToSearch);
            offset ++;
        }

        /*
         * Subdomain pin information are only returned if there is
         * no direct match and a parent domain has includeSubdomains directive
         * for offset > 1, a ping is returned only if includeSubdomains directive is present
         */
        if (null != result && !result.isSubdomainsIncluded() && offset > 1) {
            return null;
        }

        // check the max age, if expired returns null
        if (null != result && nowInMillis > result.getExpirationDateFromEpoch()) {
            return null;
        }
        return result;
    }

    private String sanitizeHostname(String hostname) {
        return hostname.replace("www.", "");
    }

    private boolean equalsString(String str1, String str2) {
        if (str1 == str2) {
            return true;
        }
        if (str1 == null) {
            return str2.equals(str1);
        }
        return str1.equals(str2);
    }

    private String getHostnameToSearch(String[] hostnameSegments, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int index = offset; index < hostnameSegments.length; index ++) {
            sb.append(hostnameSegments[index]).append(".");
        }
        // remove trailing .
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    public Collection<HPKPHeader> getHeaders() {
        return Collections.unmodifiableCollection(hostHeaders.values());
    }
}
