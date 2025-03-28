package dod.p1.keycloak.registration;

/**
 * Exception thrown when there is an error parsing a certificate.
 */
public class CertificateParsingException extends Exception {

    /**
     * Constructs a new CertificateParsingException with the specified detail message.
     *
     * @param message the detail message
     */
    public CertificateParsingException(final String message) {
        super(message);
    }

    /**
     * Constructs a new CertificateParsingException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public CertificateParsingException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
