package okhttp3;

import okhttp3.internal.Util;
import okhttp3.internal.framed.Header;
import okhttp3.internal.http.HeaderException;
import okio.ByteString;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.cert.Certificate;

/**
 * Created by rmaalej on 2/5/16.
 */
public final class HPKPinner {
    public static final String PUBLIC_KEY_PINS_HEADER_NAME = "Public-Key-Pins";

    private final HPKPinStore hpkPinStore;

    public HPKPinner(HPKPinStore hpkPinStore) {
        this.hpkPinStore = hpkPinStore;
    }

    public void pinHost(String hostname, Response response, Certificate... certificates)
            throws SSLPeerUnverifiedException {

        HPKPHeader receivedHeaderForHost;
        HPKPHeader existingHeaderForHost = hpkPinStore.findPinningInformation(hostname);
        String hpkHeaderValue = response.header(PUBLIC_KEY_PINS_HEADER_NAME);

        // existing host, should perform pin validation
        if(null != existingHeaderForHost) {
            try {
                receivedHeaderForHost = HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS_HEADER_NAME, hpkHeaderValue));
                hpkPinStore.add(hostname, receivedHeaderForHost);
                pin(existingHeaderForHost, certificates);
            } catch (Exception e) {
                throw new SSLPeerUnverifiedException("HPK Pinning has failed.");
            }
        } else {
            // add the host if it's a valid hpk pin
            try {
                receivedHeaderForHost = HPKPHeader.fromHeader(new Header(PUBLIC_KEY_PINS_HEADER_NAME, hpkHeaderValue));
                pin(receivedHeaderForHost, certificates);
                hpkPinStore.add(hostname, receivedHeaderForHost);
            } catch (SSLPeerUnverifiedException ssle) {
                // Pins associated with this host don't match the certificates returned by this host
                throw ssle;
            } catch(Exception ex) {
                // Received invalid HPK header, should log this somewhere,
                // ignoring the header as per the RFC7469, section 2.3.1
            }
        }
    }

    private void pin(HPKPHeader hPKPHeader, Certificate... certificates)
            throws SSLPeerUnverifiedException {

        for (Certificate cert : certificates) {
            String hexHash = pinCertificate(cert);
            if (hPKPHeader.getPins().contains(hexHash)) {
                return;
            }
        }

        throw new SSLPeerUnverifiedException("HPK Pinning has failed.");
    }

    public static String pinCertificate(java.security.cert.Certificate certificate) {
        if (!(certificate instanceof java.security.cert.X509Certificate)) {
            throw new IllegalArgumentException("HPK pinning requires X509 certificates");
        }
        return sha256((java.security.cert.X509Certificate) certificate).base64();
    }

    private static ByteString sha256(java.security.cert.X509Certificate x509Certificate) {
        return Util.sha256(ByteString.of(x509Certificate.getPublicKey().getEncoded()));
    }
}
