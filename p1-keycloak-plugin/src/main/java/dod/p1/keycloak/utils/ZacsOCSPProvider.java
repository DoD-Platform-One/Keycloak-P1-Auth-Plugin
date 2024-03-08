package dod.p1.keycloak.utils;

import org.keycloak.crypto.def.BCOCSPProvider;
import org.keycloak.models.KeycloakSession;

import java.net.URI;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import java.util.Date;
import java.util.List;

/**
 * Custom OCSP (Online Certificate Status Protocol) provider for Zacs.
 *
 * <p>This class extends the {@link BCOCSPProvider} and provides additional methods for checking
 * the revocation status of X.509 certificates using OCSP.</p>
 *
 */
public class ZacsOCSPProvider extends BCOCSPProvider {

    /**
     * Checks the revocation status of the given X.509 certificate using OCSP.
     *
     * @param session           The Keycloak session.
     * @param cert              The X.509 certificate to check.
     * @param issuerCertificate The issuer's X.509 certificate.
     * @param responderURIs     List of responder URIs.
     * @param responderCert     Responder's X.509 certificate.
     * @param date              The date for which to check the revocation status.
     * @return The OCSP revocation status.
     * @throws CertPathValidatorException If there is an issue with the certificate path validation.
     */
    @Override
    protected OCSPRevocationStatus check(
                   final KeycloakSession session,
                   final X509Certificate cert,
                   final X509Certificate issuerCertificate,
                   final List<URI> responderURIs,
                   final X509Certificate responderCert,
                   final Date date) throws CertPathValidatorException {
        return super.check(session, cert, issuerCertificate, responderURIs, responderCert, date);
    }

    /**
     * Retrieves the list of responder URIs for the given X.509 certificate.
     *
     * @param cert The X.509 certificate.
     * @return The list of responder URIs.
     * @throws CertificateEncodingException If there is an issue encoding the certificate.
     */
    @Override
    protected List<String> getResponderURIs(final X509Certificate cert) throws CertificateEncodingException {
        return super.getResponderURIs(cert);
      }

    /**
     * Public method to retrieve the list of responder URIs for the given X.509 certificate.
     *
     * @param cert The X.509 certificate.
     * @return The list of responder URIs.
     * @throws CertificateEncodingException If there is an issue encoding the certificate.
     */
    public List<String> getResponderURIsPublic(final X509Certificate cert) throws CertificateEncodingException {
        return getResponderURIs(cert);
    }
}
