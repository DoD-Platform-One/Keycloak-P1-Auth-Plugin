package dod.p1.keycloak.utils;

// BouncyCastle Imports
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

// Java Standard Library Imports
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;
import java.net.URI;
import java.io.IOException;

// Java Security Imports
import java.security.Security;
import java.security.GeneralSecurityException;

// Java Certificate Imports
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CRLReason;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertificateEncodingException; // Added Import
import java.security.cert.X509Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

// Logging Imports
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

// Keycloak Imports
import org.keycloak.crypto.def.BCOCSPProvider;
import org.keycloak.models.KeycloakSession;

// Utility Imports
import org.keycloak.jose.jwe.JWEUtils;
import org.keycloak.Config;

// BouncyCastle Provider Import
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * OCSP provider utility for handling OCSP validation and configuration.
 * <p>
 * This class includes configurations for excluded responders, mocked responders, and ensures that
 * the BouncyCastle security provider is added during initialization.
 * </p>
 */
public class ZacsOCSPProvider extends BCOCSPProvider {

    /**
     * Logger for the {@code ZacsOCSPProvider} class.
     * <p>
     * Used to log information, warnings, and errors related to OCSP operations.
     * </p>
     */
    private static final Logger LOGGER = LogManager.getLogger(ZacsOCSPProvider.class);

    /**
     * A utility for formatting and parsing hexadecimal strings.
     */
    private static final HexFormat HEX_FORMAT = HexFormat.of(); // Initialize HexFormat

    /**
     * List of OCSP responders that should not use a nonce during OCSP requests.
     * <p>
     * This configuration is loaded dynamically through the {@link #loadNonceExcludedResponders()} method.
     * </p>
     */
    private static final List<String> NONCE_EXCLUDED_RESPONDERS = loadNonceExcludedResponders();

    /**
     * List of OCSP responders to be mocked during testing or development.
     * <p>
     * This configuration is loaded dynamically through the {@link #loadOcspIgnoreList()} method.
     * </p>
     */
    private static final List<String> OCSP_IGNORED_RESPONDERS = loadOcspIgnoreList();

    static {
        // Add BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.info("ZacsOCSPProvider: BouncyCastleProvider added to security providers.");
    }

    /**
     * Constructs an instance of {@code ZacsOCSPProvider}.
     * <p>
     * Logs the instantiation of the provider.
     * </p>
     */
    public ZacsOCSPProvider() {
        LOGGER.info("ZacsOCSPProvider: ZacsOCSPProvider instantiated");
    }

    /**
     * Constructs an instance of {@code ZacsOCSPProvider} with a custom OCSP ignore
     * list.
     *
     * @param ocspIgnoreList List of OCSP responders to be ignored.
     */
    public ZacsOCSPProvider(final List<String> ocspIgnoreList) {
        LOGGER.info("ZacsOCSPProvider: ZacsOCSPProvider instantiated with OCSP ignore list: {}", ocspIgnoreList);
        OCSP_IGNORED_RESPONDERS.clear();
        OCSP_IGNORED_RESPONDERS.addAll(ocspIgnoreList);
    }

    /**
     * Loads the list of OCSP responders that should be mocked from Keycloak
     * configuration.
     *
     * @return List of responder hostnames as strings.
     */
    private static List<String> loadOcspIgnoreList() {
        List<String> ignoredResponders = new LinkedList<>();
        try {
            String responders = Config.scope("babyYodaOcsp").get("ignoreList", "");
            if (responders != null) {
                responders = responders.trim();
                if (!responders.isEmpty()) {
                    // Split by commas and trim spaces - using a safer regex pattern
                    String[] parts = responders.split(",");
                    List<String> trimmedParts = new ArrayList<>(parts.length);
                    for (String part : parts) {
                        trimmedParts.add(part.trim());
                    }
                    ignoredResponders = trimmedParts;
                    LOGGER.info("ZacsOCSPProvider: OCSP ignored responders loaded: {}", ignoredResponders);
                } else {
                    LOGGER.info("ZacsOCSPProvider: No responders are ignored for OCSP checks.");
                }
            } else {
                LOGGER.info("ZacsOCSPProvider: No responders are ignored for OCSP checks (null config).");
            }
        } catch (Exception e) {
            LOGGER.warn("ZacsOCSPProvider: Error loading OCSP ignored responders: {}", e.getMessage());
        }
        return ignoredResponders;
    }

    /**
     * Loads the list of OCSP responders that should not use nonce from Keycloak configuration.
     *
     * @return List of responder hostnames as strings.
     */
    private static List<String> loadNonceExcludedResponders() {
        List<String> excludedResponders = new LinkedList<>();
        try {
            String responders = Config.scope("babyYodaOcsp").get("nonceIgnoreList", "");
            if (responders != null) {
                responders = responders.trim();
                if (!responders.isEmpty()) {
                    // Split by commas and trim spaces - using a safer regex pattern
                    String[] parts = responders.split(",");
                    List<String> trimmedParts = new ArrayList<>(parts.length);
                    for (String part : parts) {
                        trimmedParts.add(part.trim());
                    }
                    excludedResponders = trimmedParts;
                    LOGGER.info("ZacsOCSPProvider: Nonce excluded responders loaded: {}", excludedResponders);
                } else {
                    LOGGER.info("ZacsOCSPProvider: No responders are excluded from nonce usage.");
                }
            } else {
                LOGGER.info("ZacsOCSPProvider: No responders are excluded from nonce usage (null config).");
            }
        } catch (Exception e) {
            LOGGER.warn("ZacsOCSPProvider: Error loading nonce excluded responders: {}", e.getMessage());
        }
        return excludedResponders;
    }

    /**
     * Overrides the check method to handle OCSP verification, including mocking for specified responders.
     *
     * @param session           The Keycloak session.
     * @param cert              The X.509 certificate to check.
     * @param issuerCertificate The issuer's X.509 certificate.
     * @param responderURIs     List of responder URIs.
     * @param responderCert     Responder's X.509 certificate (initially null).
     * @param date              The date for which to check the revocation status.
     * @return The OCSP revocation status.
     * @throws CertPathValidatorException If there is an issue with the certificate path validation.
     */
    // CHECKSTYLE:OFF
    @Override
    public OCSPRevocationStatus check(
            final KeycloakSession session,
            final X509Certificate cert,
            final X509Certificate issuerCertificate,
            final List<URI> responderURIs,
            final X509Certificate responderCert, // Initially null
            final Date date) throws CertPathValidatorException {

        LOGGER.info("ZacsOCSPProvider: ZacsOCSPProvider.check() method called");

        validateResponderURIs(responderURIs);
        logDebugInfo();

        try {
            // Create certificate ID and select responder URI
            JcaCertificateID certID = createCertificateID(issuerCertificate, cert);
            URI selectedResponderURI = responderURIs.get(0);
            String responderHost = selectedResponderURI.getHost().toLowerCase();

            LOGGER.info("ZacsOCSPProvider: Selected responder URI: {}", selectedResponderURI);
            LOGGER.info("ZacsOCSPProvider: Selected responder Host: {}", responderHost);

            // Check if we should mock the OCSP response
            if (OCSP_IGNORED_RESPONDERS.contains(responderHost)) {
                return createMockOCSPResponse(responderHost);
            }

            // Build and send OCSP request
            OCSPRequestInfo requestInfo = buildOCSPRequest(certID, selectedResponderURI, responderHost);
            org.bouncycastle.cert.ocsp.OCSPResp ocspResp =
                    getResponse(session, requestInfo.request, selectedResponderURI);

            return processOCSPResponse(ocspResp, issuerCertificate, date, certID,
                    requestInfo.nonce, requestInfo.enforceNonce, selectedResponderURI);

        } catch (OperatorCreationException e) {
            LOGGER.error("ZacsOCSPProvider: Failed to create DigestCalculatorProvider: {}", e.getMessage());
            throw new CertPathValidatorException("OCSP check failed due to operator creation error.", e);
        } catch (OCSPRequestBuildingException | OcspNonceGenerationException e) {
            LOGGER.error("ZacsOCSPProvider: Failed to build OCSP request: {}", e.getMessage());
            throw new CertPathValidatorException("OCSP check failed due to request building error.", e);
        } catch (OCSPException e) {
            LOGGER.error("ZacsOCSPProvider: OCSP exception: {}", e.getMessage());
            throw new CertPathValidatorException("OCSP check failed due to OCSP exception.", e);
        } catch (Exception e) {
            LOGGER.warn("ZacsOCSPProvider: OCSP check failed", e);
            throw new CertPathValidatorException("OCSP check failed", e);
        }
    }

    /**
     * Validates that there is at least one responder URI.
     *
     * @param responderURIs The list of responder URIs.
     */
    private void validateResponderURIs(final List<URI> responderURIs) {
        if (responderURIs == null || responderURIs.isEmpty()) {
            LOGGER.warn("ZacsOCSPProvider: No responder URIs provided. Skipping OCSP check.");
            throw new IllegalArgumentException("Need at least one responder URI");
        }
    }

    /**
     * Logs debug information about OCSP configuration.
     */
    private void logDebugInfo() {
        LOGGER.debug("ZacsOCSPProvider: OCSP Nonce Ignore List: {}", NONCE_EXCLUDED_RESPONDERS);
        LOGGER.debug("ZacsOCSPProvider: OCSP Ignore List for Mocking: {}", OCSP_IGNORED_RESPONDERS);
    }

    /**
     * Creates a certificate ID for OCSP request.
     *
     * @param issuerCertificate The issuer certificate.
     * @param cert The certificate to check.
     * @return The certificate ID.
     * @throws OperatorCreationException If there is an error creating the digest calculator.
     */
    private JcaCertificateID createCertificateID(
            final X509Certificate issuerCertificate,
            final X509Certificate cert) throws OperatorCreationException, OCSPException, CertificateEncodingException {
        org.bouncycastle.operator.DigestCalculatorProvider digestProvider =
                new JcaDigestCalculatorProviderBuilder().build();

        JcaCertificateID certID = new JcaCertificateID(
                digestProvider.get(CertificateID.HASH_SHA1),
                issuerCertificate,
                cert.getSerialNumber());

        LOGGER.debug("ZacsOCSPProvider: Created CertificateID for serial number: {}", cert.getSerialNumber());
        return certID;
    }

    /**
     * Creates a mock OCSP response for ignored responders.
     *
     * @param responderHost The responder host.
     * @return A mock OCSP revocation status.
     */
    private OCSPRevocationStatus createMockOCSPResponse(final String responderHost) {
        LOGGER.info("ZacsOCSPProvider: Responder {} is in OCSP ignore list. Mocking OCSP "
                + "check as successful.", responderHost);
        return new BCOCSPProvider.OCSPRevocationStatus() {
            @Override
            public RevocationStatus getRevocationStatus() {
                return BCOCSPProvider.RevocationStatus.GOOD;
            }

            @Override
            public java.security.cert.CRLReason getRevocationReason() {
                return java.security.cert.CRLReason.UNSPECIFIED;
            }

            @Override
            public Date getRevocationTime() {
                return null;
            }
        };
    }

    /**
     * Container class for OCSP request information.
     */
    private static class OCSPRequestInfo {
        final org.bouncycastle.cert.ocsp.OCSPReq request;
        final DEROctetString nonce;
        final boolean enforceNonce;

        OCSPRequestInfo(org.bouncycastle.cert.ocsp.OCSPReq request, DEROctetString nonce, boolean enforceNonce) {
            this.request = request;
            this.nonce = nonce;
            this.enforceNonce = enforceNonce;
        }
    }

    /**
     * Exception thrown when there is an error building an OCSP request.
     */
    private static class OCSPRequestBuildingException extends Exception {
        OCSPRequestBuildingException(final String message, final Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Builds an OCSP request.
     *
     * @param certID The certificate ID.
     * @param selectedResponderURI The selected responder URI.
     * @param responderHost The responder host.
     * @return The OCSP request information.
     * @throws OCSPRequestBuildingException If there is an error building the request.
     * @throws OcspNonceGenerationException If there is an error generating the nonce.
     * @throws OCSPException If there is an error with the OCSP request.
     */
    private OCSPRequestInfo buildOCSPRequest(
            final JcaCertificateID certID,
            final URI selectedResponderURI,
            final String responderHost) throws
                OCSPRequestBuildingException,
                OcspNonceGenerationException,
                OCSPException {

        org.bouncycastle.cert.ocsp.OCSPReqBuilder reqBuilder = new org.bouncycastle.cert.ocsp.OCSPReqBuilder();
        reqBuilder.addRequest(certID);

        // Determine whether to enforce nonce
        boolean enforceNonce = !NONCE_EXCLUDED_RESPONDERS.contains(responderHost);
        DEROctetString requestNonce = null;

        if (!enforceNonce) {
            LOGGER.info("ZacsOCSPProvider: Skipping nonce verification for responder: {}", selectedResponderURI);
        } else {
            // Generate and add nonce
            byte[] nonceBytes = generateNonce();
            String nonceHex = HEX_FORMAT.formatHex(nonceBytes);
            LOGGER.debug("ZacsOCSPProvider: Sending nonce in OCSP request (Hex): {}", nonceHex);

            DEROctetString wrappedNonce = new DEROctetString(nonceBytes);
            requestNonce = wrappedNonce;

            org.bouncycastle.asn1.x509.Extension nonceExtension = new org.bouncycastle.asn1.x509.Extension(
                    OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, wrappedNonce);
            org.bouncycastle.asn1.x509.Extensions extensions =
                    new org.bouncycastle.asn1.x509.Extensions(nonceExtension);
            reqBuilder.setRequestExtensions(extensions);

            LOGGER.info("ZacsOCSPProvider: Enforcing nonce in OCSP request.");
        }

        // Build OCSP request
        try {
            org.bouncycastle.cert.ocsp.OCSPReq ocspReq = reqBuilder.build();
            logOCSPRequest(ocspReq, enforceNonce);

            return new OCSPRequestInfo(ocspReq, requestNonce, enforceNonce);
        } catch (OCSPException e) {
            LOGGER.error("ZacsOCSPProvider: OCSP exception while building request: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            LOGGER.error("ZacsOCSPProvider: Failed to build OCSP request: {}", e.getMessage());
            throw new OCSPRequestBuildingException("Failed to build OCSP request", e);
        }
    }

    /**
     * Logs the OCSP request.
     *
     * @param ocspReq The OCSP request.
     * @param enforceNonce Whether nonce is enforced.
     */
    private void logOCSPRequest(final org.bouncycastle.cert.ocsp.OCSPReq ocspReq, final boolean enforceNonce) {
        if (enforceNonce) {
            LOGGER.debug("ZacsOCSPProvider: OCSP Request with nonce sent: {}",
                () -> {
                    try {
                        return HEX_FORMAT.formatHex(ocspReq.getEncoded());
                    } catch (IOException e) {
                        LOGGER.debug("ZacsOCSPProvider: Unable to encode OCSP request for logging", e);
                        return "encoding failed";
                    }
                });
        } else {
            LOGGER.debug("ZacsOCSPProvider: OCSP Request without nonce sent: {}",
                () -> {
                    try {
                        return HEX_FORMAT.formatHex(ocspReq.getEncoded());
                    } catch (IOException e) {
                        LOGGER.debug("ZacsOCSPProvider: Unable to encode OCSP request for logging", e);
                        return "encoding failed";
                    }
                });
        }
    }

    /**
     * Processes the OCSP response.
     *
     * @param ocspResp The OCSP response.
     * @param issuerCertificate The issuer certificate.
     * @param date The date for validation.
     * @param certID The certificate ID.
     * @param requestNonce The request nonce.
     * @param enforceNonce Whether nonce is enforced.
     * @param selectedResponderURI The selected responder URI.
     * @return The OCSP revocation status.
     * @throws CertPathValidatorException If there is an error processing the response.
     */
    private OCSPRevocationStatus processOCSPResponse(
            final org.bouncycastle.cert.ocsp.OCSPResp ocspResp,
            final X509Certificate issuerCertificate,
            final Date date,
            final JcaCertificateID certID,
            final DEROctetString requestNonce,
            final boolean enforceNonce,
            final URI selectedResponderURI) throws CertPathValidatorException, OCSPException {

        LOGGER.info("ZacsOCSPProvider: Received OCSP response from responder {} with status {}",
                selectedResponderURI, ocspResp.getStatus());

        // Log the raw OCSP response for debugging
        logOcspResponse(ocspResp);

        if (!(ocspResp.getResponseObject() instanceof BasicOCSPResp)) {
            LOGGER.error("ZacsOCSPProvider: Invalid OCSP response object: {}", ocspResp.getResponseObject());
            throw new CertPathValidatorException("Invalid OCSP response.");
        }

        BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
        X509Certificate extractedResponderCert = extractResponderCert(basicResp, issuerCertificate);

        if (extractedResponderCert == null) {
            throw new CertPathValidatorException("ZacsOCSPProvider: Unable to extract responder "
                    + "certificate from OCSP response.");
        }

        return processBasicOCSPResponse(issuerCertificate, extractedResponderCert, date, certID,
                requestNonce, basicResp, enforceNonce);
    }
    // CHECKSTYLE:ON

    /**
     * Logs the OCSP response for debugging purposes.
     *
     * @param ocspResp The OCSP response to log.
     */
    private void logOcspResponse(final org.bouncycastle.cert.ocsp.OCSPResp ocspResp) {
        try {
            byte[] rawResponse = ocspResp.getEncoded();
            String rawResponseHex = HEX_FORMAT.formatHex(rawResponse);
            LOGGER.trace("ZacsOCSPProvider: Raw OCSP Response (Hex): {}", rawResponseHex);
        } catch (IOException e) {
            LOGGER.warn("ZacsOCSPProvider: Failed to encode OCSP response for logging: {}",
                    e.getMessage());
        }
    }

    /**
     * Generates a nonce value for OCSP requests using JWEUtils.
     *
     * @return A byte array representing the nonce.
     * @throws OcspNonceGenerationException If nonce generation fails.
     */
    private byte[] generateNonce() throws OcspNonceGenerationException {
        try {
            // CHECKSTYLE:OFF
            byte[] nonceBytes = JWEUtils.generateSecret(16); // Generate 16-byte nonce
            // CHECKSTYLE:ON
            String nonceHex = HEX_FORMAT.formatHex(nonceBytes);
          LOGGER.debug("ZacsOCSPProvider: Generated nonce (Hex): {}", nonceHex);
            return nonceBytes;
        } catch (Exception e) {
            LOGGER.error("ZacsOCSPProvider: Failed to generate nonce using JWEUtils: {}", e.getMessage());
            throw new OcspNonceGenerationException("Nonce generation failed", e);
        }
    }

    /**
     * Custom exception for nonce generation failures.
     */
    private static class OcspNonceGenerationException extends Exception {
        OcspNonceGenerationException(
            final String message,
            final Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Processes the BasicOCSPResp and verifies its integrity, including nonce validation and response signature.
     *
     * @param issuerCertificate    The issuer's X.509 certificate.
     * @param responderCertificate The responder's X.509 certificate.
     * @param date                 The date of validation.
     * @param certificateID        The OCSP request certificate ID.
     * @param requestNonce         The OCSP request nonce (optional).
     * @param basicOcspResponse    The OCSP response from the server.
     * @param enforceNonce         Indicates whether nonce was enforced in the request.
     * @return The OCSPRevocationStatus (Good, Revoked, or Unknown).
     * @throws CertPathValidatorException If there is an error in validating the OCSP response.
     */
    // CHECKSTYLE:OFF
    private OCSPRevocationStatus processBasicOCSPResponse(
            final X509Certificate issuerCertificate,
            final X509Certificate responderCertificate,
            final Date date,
            final JcaCertificateID certificateID,
            final DEROctetString requestNonce,
            final BasicOCSPResp basicOcspResponse,
            final boolean enforceNonce)
            throws CertPathValidatorException {

        SingleResp expectedResponse = null;
        for (SingleResp singleResponse : basicOcspResponse.getResponses()) {
            if (compareCertIDs(certificateID, singleResponse.getCertID())) {
                expectedResponse = singleResponse;
                break;
            }
        }

        if (expectedResponse != null) {
            verifyResponse(basicOcspResponse, issuerCertificate, responderCertificate, requestNonce,
                    date, enforceNonce);
            return singleResponseToRevocationStatus(expectedResponse);
        } else {
            throw new CertPathValidatorException("ZacsOCSPProvider: OCSP response does not include a "
                    + "response for a certificate supplied in the OCSP request");
        }
    }
    // CHECKSTYLE:ON

    /**
     * Compares two CertificateID objects.
     *
     * @param idLeft  The first CertificateID.
     * @param idRight The second CertificateID.
     * @return True if both CertificateIDs are equal, false otherwise.
     */
    private boolean compareCertIDs(final JcaCertificateID idLeft, final CertificateID idRight) {
        if (idLeft == idRight) {
            return true;
        }
        if (idLeft == null || idRight == null) {
            return false;
        }

        return Arrays.equals(idLeft.getIssuerKeyHash(), idRight.getIssuerKeyHash())
                && Arrays.equals(idLeft.getIssuerNameHash(), idRight.getIssuerNameHash())
                && idLeft.getSerialNumber().equals(idRight.getSerialNumber());
    }

    /**
     * Verifies the OCSP response. Nonce verification is skipped if not enforced.
     *
     * @param basicOcspResponse    The OCSP response to verify.
     * @param issuerCertificate    The issuer certificate.
     * @param responderCertificate The responder certificate.
     * @param requestNonce         The nonce from the OCSP request (if enforced).
     * @param date                 The date for which the verification is performed.
     * @param enforceNonce         Indicates whether nonce was enforced in the request.
     * @throws CertPathValidatorException If there is an issue with the verification.
     */
    private void verifyResponse(
            final BasicOCSPResp basicOcspResponse,
            final X509Certificate issuerCertificate,
            final X509Certificate responderCertificate,
            final DEROctetString requestNonce,
            final Date date,
            final boolean enforceNonce) throws CertPathValidatorException {

      LOGGER.debug("ZacsOCSPProvider: Verifying OCSP response integrity.");

        // Log whether the response has extensions
      LOGGER.debug("ZacsOCSPProvider: OCSP response has extensions: {}", basicOcspResponse.hasExtensions());

        // Perform nonce verification if nonce was enforced
        if (enforceNonce && requestNonce != null) {
          LOGGER.debug("ZacsOCSPProvider: Enforcing nonce verification.");

            Extension responseNonce = basicOcspResponse.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

            if (responseNonce == null) {
                throw new CertPathValidatorException("ZacsOCSPProvider: Nonce missing in OCSP response.");
            }

            try {
                // Directly retrieve the nonce bytes without parsing as ASN1OctetString
                byte[] receivedNonce = responseNonce.getExtnValue().getOctets();

                // Convert both sent and received nonces to Hex for logging
                String sentNonceHex = HEX_FORMAT.formatHex(requestNonce.getOctets());
                String receivedNonceHex = HEX_FORMAT.formatHex(receivedNonce);

              LOGGER.debug("ZacsOCSPProvider: Sent nonce (Hex): {}", sentNonceHex);
              LOGGER.debug("ZacsOCSPProvider: Received nonce (Hex): {}", receivedNonceHex);

                // Compare the nonces
                if (!Arrays.equals(requestNonce.getOctets(), receivedNonce)) {
                    throw new CertPathValidatorException("ZacsOCSPProvider: Nonces do not match.");
                } else {
                  LOGGER.debug("ZacsOCSPProvider: Nonce verification succeeded.");
                }

            } catch (IllegalArgumentException e) {
                LOGGER.warn("ZacsOCSPProvider: Failed to parse nonce extension: {}", e.getMessage());
                throw new CertPathValidatorException("ZacsOCSPProvider: Invalid nonce extension in OCSP response.", e);
            }
        } else {
            LOGGER.info("ZacsOCSPProvider: Nonce was not enforced in the OCSP request. Skipping nonce verification.");
        }

        // Validate the responder's certificate
        validateResponderCertificate(responderCertificate, issuerCertificate, date);

        // Verify the signature of the OCSP response
        if (verifySignature(basicOcspResponse, responderCertificate)) {
          LOGGER.debug("ZacsOCSPProvider: OCSP response signature is valid.");
        } else {
            throw new CertPathValidatorException("ZacsOCSPProvider: Invalid OCSP response signature.");
        }

        // Check response validity period
        checkResponseValidity(basicOcspResponse, date);
    }

    /**
     * Validates the responder's certificate.
     *
     * @param responderCertificate The responder's X.509 certificate.
     * @param issuerCertificate    The issuer's X.509 certificate.
     * @param date                 The date for certificate validity check.
     * @throws CertPathValidatorException If validation fails.
     */
    private void validateResponderCertificate(
            final X509Certificate responderCertificate,
            final X509Certificate issuerCertificate,
            final Date date) throws CertPathValidatorException {

        if (responderCertificate == null) {
            throw new CertPathValidatorException("ZacsOCSPProvider: Responder certificate is null.");
        }

        // Check if the responder certificate is issued by the issuer certificate
        try {
            responderCertificate.verify(issuerCertificate.getPublicKey());
          LOGGER.debug("ZacsOCSPProvider: Responder certificate is issued by the issuer certificate.");
        } catch (GeneralSecurityException e) {
            throw new CertPathValidatorException("ZacsOCSPProvider: Responder certificate verification failed.", e);
        }

        // Check for OCSP Signing in Extended Key Usage
        try {
            List<String> extendedKeyUsages = responderCertificate.getExtendedKeyUsage();
            if (extendedKeyUsages == null || !extendedKeyUsages.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
                throw new CertPathValidatorException("ZacsOCSPProvider: Responder certificate does not have "
                        + "OCSP Signing extended key usage.");
            }
          LOGGER.debug("ZacsOCSPProvider: Responder certificate has OCSP Signing extended key usage.");
        } catch (CertificateParsingException e) {
            throw new CertPathValidatorException("ZacsOCSPProvider: Failed to parse responder certificate's "
                    + "extended key usage.", e);
        }

        // Check certificate validity
        try {
            if (date == null) {
                responderCertificate.checkValidity();
            } else {
                responderCertificate.checkValidity(date);
            }
          LOGGER.debug("ZacsOCSPProvider: Responder certificate is within its validity period.");
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            throw new CertPathValidatorException("ZacsOCSPProvider: Responder certificate is not valid.", e);
        }
    }

    /**
     * Verifies the signature of the OCSP response.
     *
     * @param basicOcspResponse The OCSP response.
     * @param cert              The responder's certificate.
     * @return True if the signature is valid, false otherwise.
     */
    private boolean verifySignature(final BasicOCSPResp basicOcspResponse, final X509Certificate cert) {
        try {
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC") // Use "BC" as the provider name
                    .build(cert.getPublicKey());
            boolean isValid = basicOcspResponse.isSignatureValid(verifierProvider);
          LOGGER.debug("ZacsOCSPProvider: OCSP response signature verification result: {}", isValid);
            return isValid;
        } catch (OperatorCreationException | OCSPException e) {
            LOGGER.warn("ZacsOCSPProvider: Unable to verify signature: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Checks the validity period of the OCSP response.
     *
     * @param basicOcspResponse The OCSP response.
     * @param date              The date for validation.
     * @throws CertPathValidatorException If the response is outside the valid time range.
     */
    private void checkResponseValidity(
            final BasicOCSPResp basicOcspResponse,
            final Date date) throws CertPathValidatorException {

        final long timeSkewMillis = 5L * 60 * 1000; // 5 minutes

        final Date currentDate = (date != null) ? date : new Date();

        for (SingleResp singleResp : basicOcspResponse.getResponses()) {
            final Date thisUpdate = singleResp.getThisUpdate();
            final Date nextUpdate = singleResp.getNextUpdate();

            if (thisUpdate != null) {
                final Date thisUpdateMinusSkew = new Date(thisUpdate.getTime() - timeSkewMillis);

                if (currentDate.before(thisUpdateMinusSkew)) {
                    throw new CertPathValidatorException("ZacsOCSPProvider: OCSP response is not yet valid.");
                }

                if (nextUpdate != null) {
                    final Date nextUpdatePlusSkew = new Date(nextUpdate.getTime() + timeSkewMillis);
                    if (currentDate.after(nextUpdatePlusSkew)) {
                        throw new CertPathValidatorException("ZacsOCSPProvider: OCSP response has expired.");
                    }
                }
            }
        }

      LOGGER.debug("ZacsOCSPProvider: OCSP response is within the valid time range.");
    }

    /**
     * Converts a SingleResp to OCSPRevocationStatus.
     *
     * @param singleResponse The single OCSP response.
     * @return The OCSPRevocationStatus.
     * @throws CertPathValidatorException If the revocation status is unrecognized.
     */
    private OCSPRevocationStatus singleResponseToRevocationStatus(final SingleResp singleResponse)
            throws CertPathValidatorException {
        final CertificateStatus certStatus = singleResponse.getCertStatus();

        CRLReason revocationReason = CRLReason.UNSPECIFIED;
        Date revocationTime = null;
        RevocationStatus status;
        if (certStatus == CertificateStatus.GOOD) {
            status = RevocationStatus.GOOD;
        } else if (certStatus instanceof RevokedStatus) {
            RevokedStatus revoked = (RevokedStatus) certStatus;
            revocationTime = revoked.getRevocationTime();
            status = RevocationStatus.REVOKED;
            if (revoked.hasRevocationReason()) {
                revocationReason = CRLReason.values()[revoked.getRevocationReason()];
            }
        } else if (certStatus instanceof UnknownStatus) {
            status = RevocationStatus.UNKNOWN;
        } else {
            throw new CertPathValidatorException("ZacsOCSPProvider: Unrecognized revocation status received "
                    + "from OCSP.");
        }

        final RevocationStatus finalStatus = status;
        final Date finalRevocationTime = revocationTime;
        final CRLReason finalRevocationReason = revocationReason;
        return new OCSPRevocationStatus() {
            @Override
            public RevocationStatus getRevocationStatus() {
                return finalStatus;
            }

            @Override
            public Date getRevocationTime() {
                return finalRevocationTime;
            }

            @Override
            public CRLReason getRevocationReason() {
                return finalRevocationReason;
            }
        };
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

    /**
     * Determines if nonce should be ignored for a given responder URI.
     *
     * @param responderURI The responder URI to check.
     * @param ignoreList The list of responders to ignore nonce for.
     * @return True if nonce should be ignored, false otherwise.
     */
    public boolean shouldIgnoreNonce(final String responderURI, final List<String> ignoreList) {
        if (responderURI == null || ignoreList == null || ignoreList.isEmpty()) {
            return false;
        }

        try {
            URI uri = URI.create(responderURI);
            String host = uri.getHost().toLowerCase();
            return ignoreList.contains(host);
        } catch (Exception e) {
            LOGGER.warn("ZacsOCSPProvider: Failed to parse responder URI: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extracts the responder's certificate from the OCSP response.
     *
     * @param basicResp         The BasicOCSPResp object.
     * @param issuerCertificate The issuer's certificate.
     * @return The responder's X509Certificate or null if not found.
     */
    protected X509Certificate extractResponderCert(
            final BasicOCSPResp basicResp, final X509Certificate issuerCertificate) {
        try {
            // Iterate through the certificates included in the OCSP response
            for (X509CertificateHolder certHolder : basicResp.getCerts()) {
                X509Certificate cert = new JcaX509CertificateConverter()
                        .setProvider("BC")
                        .getCertificate(certHolder);

                // Check if this cert is the responder's cert
                if (isResponderCertificate(cert, issuerCertificate)) {
                    LOGGER.info("ZacsOCSPProvider: Responder certificate extracted and verified.");
                    return cert;
                }
            }
        } catch (CertificateException e) {
            LOGGER.error("ZacsOCSPProvider: Failed to convert responder certificate.", e);
        }
        return null;
    }

    /**
     * Determines if a certificate is the responder's certificate.
     *
     * @param cert              The certificate to check.
     * @param issuerCertificate The issuer's certificate.
     * @return True if it is the responder's certificate, false otherwise.
     */
    private boolean isResponderCertificate(final X509Certificate cert, final X509Certificate issuerCertificate) {
        try {
            // Verify that the responder's certificate is issued by the issuer
            cert.verify(issuerCertificate.getPublicKey());

            // Check for OCSP Signing in Extended Key Usage
            List<String> extendedKeyUsages = cert.getExtendedKeyUsage();
            if (extendedKeyUsages != null && extendedKeyUsages.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
              LOGGER.debug("ZacsOCSPProvider: Certificate is authorized for OCSP Signing.");
                return true;
            } else {
                LOGGER.warn("ZacsOCSPProvider: Certificate does not have OCSP Signing extended key usage.");
            }
        } catch (GeneralSecurityException e) {
            LOGGER.warn("ZacsOCSPProvider: Responder certificate verification failed.", e);
        }
        return false;
    }
}
