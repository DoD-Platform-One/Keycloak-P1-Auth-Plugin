package dod.p1.keycloak.utils;

import org.keycloak.crypto.def.BCOCSPProvider;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.truststore.TruststoreProvider;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.security.auth.x500.X500Principal;

import org.keycloak.authentication.AuthenticationFlowContext;

/**
 * Utils class for performing OCSP Certificate Verification.
 */
public final class OCSPUtils {

    /**
     * Logger for the {@code OCSPUtils} class.
     * <p>
     * Used to log information, warnings, and errors during OCSP operations.
     * </p>
     */
    private static final Logger LOGGER = LogManager.getLogger(OCSPUtils.class);

    /**
     * Private constructor to prevent instantiation of this utility class.
     * <p>
     * This constructor throws an {@link UnsupportedOperationException} to enforce that the class is
     * used solely as a utility.
     * </p>
     */
    private OCSPUtils() {
        throw new UnsupportedOperationException("OCSP Utility class");
    }

    /**
     * Performs an OCSP check for the given certificate chain.
     *
     * @param session    The Keycloak session.
     * @param certChain  The certificate chain, where certChain[0] is the end-entity certificate.
     * @return OCSPResult object containing the result of the OCSP check.
     * @throws GeneralSecurityException if a security error occurs during the process.
     */
    public static OCSPResult performOCSPCheck(
            final KeycloakSession session,
            final X509Certificate[] certChain) throws GeneralSecurityException {
        LOGGER.debug("OCSPUtils: Performing OCSP check.");

        if (certChain == null || certChain.length == 0) {
            LOGGER.warn("OCSPUtils: No certificates provided for OCSP check.");
            return new OCSPResult(false, "No certificates provided");
        }

        X509Certificate endEntityCert = certChain[0];
        X509Certificate issuerCert = getIssuerCertificate(session, certChain);

        if (issuerCert == null) {
            LOGGER.error("OCSPUtils: No trusted CA found for issuer: {}",
                    endEntityCert.getIssuerX500Principal());
            return new OCSPResult(false, "No trusted CA found");
        }

        try {
            ZacsOCSPProvider ocspProvider = new ZacsOCSPProvider();
            List<String> responderURIs = ocspProvider.getResponderURIsPublic(endEntityCert);
            List<URI> responderURIsAsURI = responderURIs.stream()
                    .map(URI::create)
                    .collect(Collectors.toList());

            LOGGER.trace("OCSPUtils:  Cert: {} Issuer: {} ResponderURIs: {}",
                    endEntityCert, issuerCert, responderURIsAsURI.isEmpty() ? "None" : responderURIsAsURI);

            LOGGER.debug(
                "OCSPUtils: Certificate Details:\n"
                + "  Subject DN: {}\n"
                + "  Expiration Date: {}\n"
                + "  Serial Number: {}\n"
                + "  Issuer DN: {}\n"
                + "  Issuer Serial Number: {}",
                endEntityCert.getSubjectX500Principal().getName(),
                endEntityCert.getNotAfter(),
                endEntityCert.getSerialNumber(),
                issuerCert.getSubjectX500Principal().getName()
                );


            if (responderURIsAsURI.isEmpty()) {
                LOGGER.warn("OCSPUtils: No responder URIs found in certificate.");
                return new OCSPResult(false, "No responder URIs found");
            }

            // Perform OCSP check
            BCOCSPProvider.OCSPRevocationStatus ocspStatus = ocspProvider.check(
                    session,
                    endEntityCert,
                    issuerCert,
                    responderURIsAsURI,
                    null,
                    null
            );

            // Check the OCSP revocation status
            if (ocspStatus.getRevocationStatus() != BCOCSPProvider.RevocationStatus.GOOD) {
                LOGGER.warn("OCSPUtils: OCSP check failed with status: {}", ocspStatus.getRevocationStatus());
                return new OCSPResult(false, "OCSP status: " + ocspStatus.getRevocationStatus());
            } else {
                LOGGER.debug("OCSPUtils: OCSP check passed with status: {}", ocspStatus.getRevocationStatus());
                return new OCSPResult(true, null);
            }

        } catch (CertificateEncodingException e) {
            LOGGER.warn("OCSPUtils: Error while getting responder URIs from certificate: {}", e.getMessage());
            return new OCSPResult(false, "Certificate encoding error");
        }
    }

    /**
     * Identifies and retrieves the issuer's certificate from the truststore.
     *
     * @param session   The Keycloak session.
     * @param certChain The certificate chain.
     * @return The issuer's X509Certificate, or null if not found.
     * @throws GeneralSecurityException if a security error occurs during the process.
     */
    private static X509Certificate getIssuerCertificate(
            final KeycloakSession session,
            final X509Certificate[] certChain) throws GeneralSecurityException {
        X509Certificate cert = certChain[0]; // End-entity certificate
        X509Certificate issuer;
        String issuerSerialNumber;

        if (certChain.length > 1) {
            issuer = certChain[1]; // Intermediate CA certificate
        } else {
            // Attempt to extract issuer's serial number from AKI
            issuerSerialNumber = getIssuerSerialNumber(cert);
            if (issuerSerialNumber == null) {
                LOGGER.warn("OCSPUtils: Unable to extract issuer serial number from certificate.");
                // Proceed to find CA based solely on issuer's X500Principal
                issuer = findCAInTruststore(session, cert.getIssuerX500Principal(), null);
            } else {
                issuer = findCAInTruststore(session, cert.getIssuerX500Principal(), issuerSerialNumber);
            }
        }

        return issuer;
    }

    /**
     * Extracts the issuer's serial number from the Authority Key Identifier extension.
     *
     * @param cert The end-entity X509Certificate.
     * @return The issuer's serial number as a String, or null if not found.
     */
    private static String getIssuerSerialNumber(final X509Certificate cert) {
        byte[] authorityKeyIdBytes = cert.getExtensionValue("2.5.29.35"); // OID for Authority Key Identifier
        if (authorityKeyIdBytes == null) {
            LOGGER.warn("OCSPUtils: Authority Key Identifier extension is missing.");
            return null;
        }

        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(authorityKeyIdBytes))) {
            ASN1Primitive asn1Primitive = asn1InputStream.readObject();
            DEROctetString derOctetString = (DEROctetString) asn1Primitive;
            byte[] octets = derOctetString.getOctets();

            try (ASN1InputStream asn1Stream = new ASN1InputStream(new ByteArrayInputStream(octets))) {
                ASN1Primitive authorityKeyIdentifier = asn1Stream.readObject();
                AuthorityKeyIdentifier akid = AuthorityKeyIdentifier.getInstance(authorityKeyIdentifier);
                BigInteger caCertSerialNumber = akid.getAuthorityCertSerialNumber();
                if (caCertSerialNumber == null) {
                    LOGGER.warn("OCSPUtils: AuthorityCertSerialNumber is null in AKI extension.");
                    return null;
                }
                return caCertSerialNumber.toString();
            }
        } catch (IOException | ClassCastException e) {
            LOGGER.warn("OCSPUtils: Failed to extract issuer serial number: {}", e.getMessage());
            return null;
        }
    }

   /**
    * Checks if a certificate is valid and logs appropriate messages.
    *
    * @param caCert The certificate to check
    * @param matchType The type of match (exact or partial)
    * @param serialNumber The serial number of the certificate
    * @return The certificate if valid, null otherwise
    */
   private static X509Certificate validateCertificate(
           final X509Certificate caCert,
           final String matchType,
           final String serialNumber) {
       try {
           caCert.checkValidity();  // Ensure validity
           LOGGER.debug("OCSPUtils: {} match found for CA Certificate: {} (SerialNumber={})",
                   matchType, caCert.getSubjectX500Principal(), serialNumber);
           return caCert;
       } catch (CertificateExpiredException | CertificateNotYetValidException e) {
           LOGGER.warn("OCSPUtils: CA Certificate {} is not valid: {}",
                   caCert.getSubjectX500Principal(), e.getMessage());
           return null;
       }
   }

   /**
    * Finds the CA certificate in the truststore by subject name and optionally by serial number.
    *
    * @param session              The Keycloak session.
    * @param issuerPrincipal      The issuer's X500Principal.
    * @param expectedSerialNumber The expected serial number of the CA (nullable).
    * @return The matching X509Certificate, or null if no match is found.
    * @throws GeneralSecurityException if a security error occurs during the process.
    */
   public static X509Certificate findCAInTruststore(
           final KeycloakSession session,
           final X500Principal issuerPrincipal,
           final String expectedSerialNumber) throws GeneralSecurityException {

       LOGGER.debug("OCSPUtils: Searching for CA with Issuer Principal: {} and Serial Number: {}",
               issuerPrincipal, expectedSerialNumber);

       TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
       if (truststoreProvider == null || truststoreProvider.getTruststore() == null) {
           LOGGER.error("OCSPUtils: TruststoreProvider is null or truststore is unavailable.");
           return null;
       }

       // Retrieve maps with lists of certificates
       Map<X500Principal, List<X509Certificate>> rootCertsMap = truststoreProvider.getRootCertificates();
       Map<X500Principal, List<X509Certificate>> intermediateCertsMap =
           truststoreProvider.getIntermediateCertificates();

       LOGGER.debug("OCSPUtils: Loaded {} root certificate entries and {} intermediate certificate entries.",
               rootCertsMap.size(), intermediateCertsMap.size());

       // Log certificate counts
       logCertificateCounts(rootCertsMap, intermediateCertsMap);

       // Flatten the lists from both maps into a single collection
       Collection<X509Certificate> allCerts = Stream.concat(
           rootCertsMap.values().stream().flatMap(List::stream),
           intermediateCertsMap.values().stream().flatMap(List::stream)
       ).collect(Collectors.toList());

       LOGGER.debug("OCSPUtils: Iterating through all CA certificates to find a match.");

       // Find matching certificate
       X509Certificate matchingCert = findMatchingCertificate(allCerts, issuerPrincipal, expectedSerialNumber);

       if (matchingCert == null) {
           LOGGER.warn("OCSPUtils: No matching CA certificate found for issuer: {} with serial number: {}",
                   issuerPrincipal, expectedSerialNumber);
       }

       return matchingCert;
   }

   /**
    * Logs certificate counts for debugging purposes.
    *
    * @param rootCertsMap Map of root certificates
    * @param intermediateCertsMap Map of intermediate certificates
    */
   private static void logCertificateCounts(
           final Map<X500Principal, List<X509Certificate>> rootCertsMap,
           final Map<X500Principal, List<X509Certificate>> intermediateCertsMap) {
       LOGGER.debug("OCSPUtils: Root certificates count per key: {}",
           rootCertsMap.values().stream().mapToInt(List::size).boxed().collect(Collectors.toList()));
       LOGGER.debug("OCSPUtils: Intermediate certificates count per key: {}",
           intermediateCertsMap.values().stream().mapToInt(List::size).boxed().collect(Collectors.toList()));
   }

   /**
    * Finds a matching certificate in the collection based on issuer principal and serial number.
    *
    * @param certificates Collection of certificates to search
    * @param issuerPrincipal The issuer principal to match
    * @param expectedSerialNumber The expected serial number (can be null)
    * @return The matching certificate or null if not found
    */
   private static X509Certificate findMatchingCertificate(
           final Collection<X509Certificate> certificates,
           final X500Principal issuerPrincipal,
           final String expectedSerialNumber) {

       for (X509Certificate caCert : certificates) {
           // Skip certificates that don't match the subject
           if (!caCert.getSubjectX500Principal().equals(issuerPrincipal)) {
               continue;
           }

           String caCertSerialNumber = caCert.getSerialNumber().toString();
           LOGGER.debug("OCSPUtils: Checking CA Certificate: Subject={}, SerialNumber={}",
                   caCert.getSubjectX500Principal(), caCertSerialNumber);

           // Check for exact match if serial number is provided
           if (expectedSerialNumber != null && expectedSerialNumber.equals(caCertSerialNumber)) {
               X509Certificate validCert = validateCertificate(caCert, "Exact", caCertSerialNumber);
               if (validCert != null) {
                   return validCert;
               }
           } else if (expectedSerialNumber == null) { // If no serial number provided, use first valid certificate
               X509Certificate validCert = validateCertificate(caCert, "Partial", caCertSerialNumber);
               if (validCert != null) {
                   return validCert;
               }
           }
       }

       return null;
   }

    /**
     * Extracts the Common Name (CN) from the Subject DN.
     *
     * @param subjectDN The subject distinguished name.
     * @return The Common Name, or "Unknown" if it cannot be extracted.
     */
    public static String extractCommonName(final String subjectDN) {
        if (subjectDN == null || !subjectDN.contains("CN=")) {
            return "Unknown";
        }
        String[] dnComponents = subjectDN.split(",");
        for (String component : dnComponents) {
            component = component.trim();
            if (component.startsWith("CN=")) {
                // CHECKSTYLE:OFF
                return component.substring(3);
                // CHECKSTYLE:ON
            }
        }
        return "Unknown";
    }

    /**
     * Represents the result of an OCSP (Online Certificate Status Protocol) check.
     * <p>
     * This class encapsulates the outcome of the OCSP check, indicating whether the certificate is valid
     * and, if not, providing a failure reason.
     * </p>
     */
    public static class OCSPResult {
        /**
         * Indicates whether the OCSP check was successful.
         */
        private final boolean isOCSPGood;

        /**
         * The reason for failure if the OCSP check was unsuccessful.
         * <p>
         * This is {@code null} if the OCSP check was successful.
         * </p>
         */
        private final String failureReason;

        /**
         * Constructs an instance of {@code OCSPResult}.
         *
         * @param isCertificateValid a {@code boolean} indicating whether the OCSP check passed
         * @param validationError a {@code String} describing the reason for failure,
         *                        or {@code null} if the check passed
         */
        public OCSPResult(final boolean isCertificateValid, final String validationError) {
            this.isOCSPGood = isCertificateValid;
            this.failureReason = validationError;
        }

        /**
         * Returns whether the OCSP check passed.
         *
         * @return {@code true} if the OCSP check was successful, {@code false} otherwise
         */
        public boolean isOCSPGood() {
            return isOCSPGood;
        }

        /**
         * Returns the reason for OCSP check failure.
         *
         * @return a {@code String} describing the failure reason, or {@code null} if the check was successful
         */
        public String getFailureReason() {
            return failureReason;
        }
    }

    /**
     * Retrieves the certificate chain from the RequiredActionContext.
     *
     * @param context The RequiredActionContext.
     * @return The certificate chain as an array of X509Certificates, or an empty array if not found.
     */
    public static X509Certificate[] getCertificateChain(final RequiredActionContext context) {
        try {
            X509ClientCertificateLookup provider = context.getSession().getProvider(X509ClientCertificateLookup.class);
            if (provider == null) {
                LOGGER.warn("OCSPUtils: X509ClientCertificateLookup provider is not available.");
                return new X509Certificate[0];
            }
            X509Certificate[] certChain = provider.getCertificateChain(context.getHttpRequest());
            if (certChain != null && certChain.length > 0) {
                LOGGER.debug("OCSPUtils: Retrieved certificate chain with {} certificates.",
                        certChain.length);
                return certChain; // Return the entire certificate chain
            } else {
                LOGGER.warn("OCSPUtils: Certificate chain is empty.");
                return new X509Certificate[0];
            }
        } catch (GeneralSecurityException e) {
            LOGGER.error("OCSPUtils: Failed to retrieve certificate chain: {}", e.getMessage(), e);
            return new X509Certificate[0];
        }
    }

    /**
     * Retrieves the certificate chain from the authentication context.
     *
     * @param context The AuthenticationFlowContext.
     * @return The certificate chain as an array of X509Certificates, or an empty array if not found.
     */
    public static X509Certificate[] getCertificateChain(final AuthenticationFlowContext context) {
        try {
            X509ClientCertificateLookup provider = context.getSession().getProvider(X509ClientCertificateLookup.class);
            if (provider == null) {
                LOGGER.warn("OCSPCheckAuthenticator: X509ClientCertificateLookup provider is not available.");
                return new X509Certificate[0];
            }
            X509Certificate[] certChain = provider.getCertificateChain(context.getHttpRequest());
            if (certChain != null && certChain.length > 0) {
                return certChain; // Return the entire certificate chain
            } else {
                LOGGER.warn("OCSPCheckAuthenticator: Certificate chain is empty.");
                return new X509Certificate[0];
            }
        } catch (GeneralSecurityException e) {
            LOGGER.error("OCSPCheckAuthenticator: Failed to retrieve certificate chain: {}",
                    e.getMessage(), e);
            return new X509Certificate[0];
        }
    }
}
