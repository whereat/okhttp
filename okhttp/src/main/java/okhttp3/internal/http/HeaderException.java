package okhttp3.internal.http;

/**
 * Created by rmaalej on 2/9/16.
 */
public class HeaderException extends Exception {

    public HeaderException(String message) {
        super(message);
    }

    public HeaderException(String message, Throwable cause) {
        super(message, cause);
    }

    public HeaderException(Throwable cause) {
        super(cause);
    }

    public HeaderException() {
    }
}
