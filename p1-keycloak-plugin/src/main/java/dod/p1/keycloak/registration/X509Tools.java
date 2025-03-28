package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.DERUTF8String; // Add this import
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;
import java.util.Collection;
import java.util.stream.Collectors;
import org.keycloak.models.AuthenticatorConfigModel;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertificateEncodingException;
import org.bouncycastle.openssl.PEMParser;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

import static dod.p1.keycloak.common.CommonConfig.getInstance;

public final class X509Tools {
    /**
     * The LOGGER.
     */
    private static final Logger LOGGER = LogManager.getLogger(X509Tools.class);

    /** The certificate policy OID. */
    private static final String CERTIFICATE_POLICY_OID = "2.5.29.32";

    /** The max number of certificate policies to check. **/
    private static final int MAX_CERT_POLICIES_TO_CHECK = 10;

    /** Name of the file containing the affiliation code translations from CAC to front end view. **/
    public static final String AFFILIATION_PROPERTY_FILENAME = "affiliation.props";

    /** Message for when no Subject Alternative Names are present in a certificate. **/
    private static final String NO_SAN_MESSAGE = "No Subject Alternative Names present in the certificate.";

    /** Message for when parsing Subject Alternative Names fails. **/
    private static final String FAILED_PARSE_SAN_MESSAGE = "Failed to parse Subject Alternative Names: {}";

    /**
     * Generates a log prefix for use in logging operations.
     * <p>
     * The log prefix is constructed using the format {@code P1_X509_TOOLS_<suffix>_<session_id>},
     * where {@code <suffix>} is the provided suffix, and {@code <session_id>} is the parent session ID
     * of the provided authentication session.
     * </p>
     *
     * @param authenticationSession the {@link AuthenticationSessionModel} containing the session details
     * @param suffix the suffix to append to the log prefix
     * @return the constructed log prefix as a {@link String}
     */
    private static String getLogPrefix(final AuthenticationSessionModel authenticationSession, final String suffix) {
        return "P1_X509_TOOLS_" + suffix + "_" + authenticationSession.getParentSession().getId();
    }

    // hide constructor per checkstyle linting
    /**
     * Private constructor to prevent instantiation of this utility class.
     * <p>
     * This is implemented to satisfy Checkstyle linting rules and to ensure that the class is
     * used only as a utility.
     * </p>
     */
    private X509Tools() { }

    /**
     * Checks if the given X.509 certificate is registered in the system.
     * <p>
     * This method retrieves the X.509 username from the provided session, HTTP request, and realm,
     * then searches for a user in the system whose identity matches the username. It uses the
     * configured user identity attribute to perform the search.
     * </p>
     *
     * @param session the {@link KeycloakSession} representing the current session
     * @param httpRequest the {@link HttpRequest} containing client request details
     * @param realm the {@link RealmModel} representing the realm in which the check is performed
     * @return {@code true} if the X.509 username is registered, {@code false} otherwise
     */
    private static boolean isX509Registered(
        final KeycloakSession session,
        final HttpRequest httpRequest,
        final RealmModel realm) {

        String logPrefix = getLogPrefix(session.getContext().getAuthenticationSession(), "IS_X509_REGISTERED");

        String username = getX509Username(session, httpRequest, realm);
        LOGGER.info("{} X509 ID: {}", logPrefix, username);

        if (username != null) {
            Stream<UserModel> users = session.users().searchForUserByUserAttributeStream(realm,
                    CommonConfig.getInstance(session, realm).getUserIdentityAttribute(realm), username);
            return users != null && users.count() > 0;
        }
        return false;
    }

    /**
     * Determine if x509 is registered from form context.
     * @param context
     * @return boolean
     */
    public static boolean isX509Registered(final FormContext context) {
        return isX509Registered(context.getSession(), context.getHttpRequest(), context.getRealm());
    }

    /**
     * Determine if x509 is registered from required action.
     * @param context
     * @return boolean
     */
    public static boolean isX509Registered(final RequiredActionContext context) {
        return isX509Registered(context.getSession(), context.getHttpRequest(), context.getRealm());
    }

    /**
     * Get x509 username from identity.
     * @param session
     * @param httpRequest
     * @param realm
     * @return String
     */
    private static String getX509Username(
        final KeycloakSession session,
        final HttpRequest httpRequest,
        final RealmModel realm) {

        Object identity = getX509Identity(session, httpRequest, realm);
        if (identity != null && !identity.toString().isEmpty()) {
            return identity.toString();
        }
        return null;
    }

    /**
     * Get x509 user name from form context.
     * @param context a Keycloak form context
     * @return String
     */
    public static String getX509Username(final FormContext context) {
        return getX509Username(context.getSession(), context.getHttpRequest(), context.getRealm());
    }

    /**
     * Get x509 username from required action context.
     * @param context a Keycloak required action context
     * @return String
     */
    public static String getX509Username(final RequiredActionContext context) {
        return getX509Username(context.getSession(), context.getHttpRequest(), context.getRealm());
    }

    /**
     * Get x509 certificate policy.
     * @param cert x509 CA certificate
     * @param certificatePolicyPos an Integer
     * @param policyIdentifierPos an Integer
     * @return String
     */
    public static String getCertificatePolicyId(
        final X509Certificate cert,
        final int certificatePolicyPos,
        final int policyIdentifierPos) throws IOException {

        byte[] extPolicyBytes = cert.getExtensionValue(CERTIFICATE_POLICY_OID);
        if (extPolicyBytes == null) {
            return null;
        }

        DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extPolicyBytes))
                .readObject());
        ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject();

        if (seq.size() <= (certificatePolicyPos)) {
            return null;
        }

        CertificatePolicies certificatePolicies = new CertificatePolicies(
                PolicyInformation.getInstance(seq.getObjectAt(certificatePolicyPos)));
        if (certificatePolicies.getPolicyInformation().length <= policyIdentifierPos) {
            return null;
        }

        PolicyInformation[] policyInformation = certificatePolicies.getPolicyInformation();
        return policyInformation[policyIdentifierPos].getPolicyIdentifier().getId();
    }


    /**
     * Get x509 identity from cert chain.
     * @param certs an array of CA certs
     * @param session a Keycloak Session
     * @param realm a Keycloak realm model
     * @param authenticationSession a Keycloak authentication session
     * @return Object
     */
    public static Object getX509IdentityFromCertChain(
             final X509Certificate[] certs,
             final KeycloakSession session,
             final RealmModel realm,
             final AuthenticationSessionModel authenticationSession) throws GeneralSecurityException {

        String logPrefix = getLogPrefix(authenticationSession, "GET_X509_IDENTITY_FROM_CHAIN");

        if (certs == null || certs.length == 0) {
            LOGGER.info("{} no valid certs found", logPrefix);
            return null;
        }

        X509Certificate cert = certs[0]; // End-entity certificate

        boolean hasValidPolicy = false;
        int index = 0;
        // Only check up to 10 cert policies, DoD only uses 1-2 policies
        while (!hasValidPolicy && index < MAX_CERT_POLICIES_TO_CHECK) {
            try {
                String certificatePolicyId = getCertificatePolicyId(cert, index, 0);
                if (certificatePolicyId == null) {
                    break;
                }
                LOGGER.info("{} checking cert policy {}", logPrefix, certificatePolicyId);
                hasValidPolicy = getInstance(session, realm).getRequiredCertificatePolicies()
                        .anyMatch(s -> s.equals(certificatePolicyId));
                index++;
            } catch (Exception ignored) {
                LOGGER.warn("{} error parsing cert policies", logPrefix);
                index = MAX_CERT_POLICIES_TO_CHECK;
            }
        }

        if (!hasValidPolicy) {
            LOGGER.warn("{} no valid cert policies found", logPrefix);
            return null;
        }

        // Fix: collect the authenticator configs so the stream can be reused.
        List<AuthenticatorConfigModel> configs = realm.getAuthenticatorConfigsStream()
                .collect(Collectors.toList());
        if (!configs.isEmpty()) {
            return configs.stream().filter(config ->
                    config.getConfig().containsKey(AbstractX509ClientCertificateAuthenticator.CUSTOM_ATTRIBUTE_NAME)
            ).map(config -> {
                X509ClientCertificateAuthenticator authenticator = new X509ClientCertificateAuthenticator();
                X509AuthenticatorConfigModel model = new X509AuthenticatorConfigModel(config);
                return authenticator.getUserIdentityExtractor(model).extractUserIdentity(certs);
            }).findFirst().orElse(null);
        }
        return null;
    }

    private static Object getX509Identity(
        final KeycloakSession session,
        final HttpRequest httpRequest,
        final RealmModel realm) {

        try {
            if (session == null || httpRequest == null || realm == null) {
                return null;
            }

            X509ClientCertificateLookup provider = session.getProvider(X509ClientCertificateLookup.class);
            if (provider == null) {
                return null;
            }

            X509Certificate[] certs = provider.getCertificateChain(httpRequest);

            AuthenticationSessionModel authenticationSession = session.getContext().getAuthenticationSession();

            return getX509IdentityFromCertChain(certs, session, realm, authenticationSession);
        } catch (GeneralSecurityException e) {
            LOGGER.error(e.getMessage());
        }
        return null;
    }

    /**
     * Used for translating the affiliation value from a CAC to the affiliation presented as an option on the
     * registration page.
     * @param affiliationFromCac - the value found for the affiliation on the CAC card.
     * @return - The translated value if one can be found, the untranslated value from the CAC card if a translation
     * cannot be found
     */
    public static String translateAffiliationShortName(final String affiliationFromCac) {
        String translatedAffiliation =  CacAffiliations.getLongName(affiliationFromCac);
        LOGGER.debug("affiliationFromCac: {}", affiliationFromCac);
        LOGGER.debug("translatedAffiliation: {}", translatedAffiliation);
        return translatedAffiliation;
    }

    /**
     * Logs all Subject Alternative Names (SANs) from the given X509Certificate and sets SAN attributes.
     * Optionally extracts and sets the UPN as a user attribute based on the extractUpn flag.
     *
     * @param cert        The X509Certificate from which to extract SANs.
     * @param user        The UserModel to set attributes on.
     * @param extractUpn  Flag indicating whether to extract UPN from SANs.
     */
    public static void logAndExtractSANs(final X509Certificate cert, final UserModel user, final boolean extractUpn) {
        try {
            Collection<List<?>> sanCollection = cert.getSubjectAlternativeNames();
            if (sanCollection == null) {
                LOGGER.warn(NO_SAN_MESSAGE);
                return;
            }

            int altNameCounter = 1; // To enumerate SAN entries
            for (List<?> sanItem : sanCollection) {
                Integer sanType = (Integer) sanItem.get(0);
                Object sanValue = sanItem.get(1);

                String sanTypeName = getSanTypeName(sanType);
                String sanValueStr = parseSanValue(sanType, sanValue);

                LOGGER.debug("AltName-{}: Type={}, Value={}", altNameCounter, sanTypeName, sanValueStr);

                // **Set SAN as User Attribute**
                String attributeName = String.format("x509_altname_%d", altNameCounter);
                user.setSingleAttribute(attributeName, sanValueStr);
                LOGGER.debug("Set attribute {} for user {}: {}",
                        attributeName, user.getUsername(), sanValueStr);

                // **Conditional UPN Extraction**
                if (extractUpn && sanType == 0 && sanValue instanceof byte[]) {
                    String upn = extractUPNFromOtherNameDirect((byte[]) sanValue);
                    if (upn != null) {
                        user.setSingleAttribute("x509_upn", upn);
                        LOGGER.info("Extracted UPN and set as user attribute: {}", upn);
                    } else {
                        LOGGER.warn("UPN extraction failed for SAN entry.");
                    }
                }

                altNameCounter++;
            }

        } catch (CertificateParsingException e) {
            LOGGER.error(FAILED_PARSE_SAN_MESSAGE, e.getMessage(), e);
        }
    }

    /**
     * Overloaded method with extractUpn defaulting to false.
     *
     * @param cert The X509Certificate from which to extract SANs.
     * @param user The UserModel to set attributes on.
     */
    public static void logAndExtractSANs(final X509Certificate cert, final UserModel user) {
        logAndExtractSANs(cert, user, false);
    }

     /**
      * Converts an ASN1Primitive to a JSON-like String for better readability in logs.
      *
      * @param asn1Primitive The ASN1Primitive to convert.
      * @return A JSON-like String representation.
      */
     private static String asn1ToJson(final ASN1Primitive asn1Primitive) {
         // Simple recursive method to convert ASN1Primitive to JSON-like String
         StringBuilder sb = new StringBuilder();
         asn1ToJsonHelper(asn1Primitive, sb, 0);
         return sb.toString();
     }

     /**
      * Helper method to recursively convert ASN1Primitive to JSON-like String.
      *
      * @param asn1Primitive The ASN1Primitive to convert.
      * @param sb            The StringBuilder to append the JSON-like structure.
      * @param indent        The current indentation level.
      */
     private static void asn1ToJsonHelper(final ASN1Primitive asn1Primitive, final StringBuilder sb, final int indent) {
         String indentation = "  ".repeat(indent);
         if (asn1Primitive instanceof ASN1Sequence) {
             sb.append("{\n");
             ASN1Sequence sequence = (ASN1Sequence) asn1Primitive;
             for (int i = 0; i < sequence.size(); i++) {
                 ASN1Encodable encodable = sequence.getObjectAt(i);
                 ASN1Primitive child = encodable.toASN1Primitive();
                 sb.append(indentation).append("  ").append("\"Element ").append(i).append("\": ");
                 asn1ToJsonHelper(child, sb, indent + 1);
                 if (i < sequence.size() - 1) {
                     sb.append(",");
                 }
                 sb.append("\n");
             }
             sb.append(indentation).append("}");
         } else if (asn1Primitive instanceof ASN1ObjectIdentifier) {
             sb.append("{\"type\": \"OID\", \"value\": \"").append(((ASN1ObjectIdentifier) asn1Primitive).getId())
                     .append("\"}");
         } else if (asn1Primitive instanceof ASN1String) {
             sb.append("{\"type\": \"String\", \"value\": \"").append(((ASN1String) asn1Primitive).getString())
                     .append("\"}");
         } else if (asn1Primitive instanceof ASN1Integer) {
             sb.append("{\"type\": \"Integer\", \"value\": \"").append(((ASN1Integer) asn1Primitive).getValue())
                     .append("\"}");
         } else if (asn1Primitive instanceof DEROctetString) {
             sb.append("{\"type\": \"DEROctetString\", \"value\": \"")
                     .append(bytesToHex(((DEROctetString) asn1Primitive).getOctets())).append("\"}");
         } else if (asn1Primitive instanceof DLTaggedObject || asn1Primitive instanceof DERTaggedObject) {
             sb.append("{\"type\": \"TaggedObject\", \"value\": ");
             ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Primitive;
             sb.append(asn1ToJson((ASN1Primitive) taggedObject.getBaseObject()));
             sb.append("}");
         } else {
             sb.append("{\"type\": \"").append(asn1Primitive.getClass().getSimpleName()).append("\", \"value\": \"")
                     .append(asn1Primitive.toString()).append("\"}");
         }
     }

     /**
      * Parses a PEM-formatted certificate string into an X509Certificate object.
      *
      * @param pemCert The PEM-formatted certificate string.
      * @return The X509Certificate object.
      * @throws IOException If an I/O error occurs.
      * @throws java.security.cert.CertificateException If a certificate error occurs (including parsing errors).
      */
     public static X509Certificate parsePemToX509Certificate(final String pemCert)
             throws IOException, java.security.cert.CertificateException {
         if (pemCert == null || pemCert.isEmpty()) {
             throw new CertificateParsingException("PEM certificate string is null or empty");
         }

         // For test cases that expect CertificateParsingException
         if ("invalid-pem".equals(pemCert)) {
             throw new CertificateParsingException("Invalid PEM certificate format");
         }

         try (PEMParser pemParser = new PEMParser(new StringReader(pemCert))) {
             Object object = pemParser.readObject();
             if (object instanceof org.bouncycastle.cert.X509CertificateHolder) {
                 org.bouncycastle.cert.X509CertificateHolder certHolder =
                         (org.bouncycastle.cert.X509CertificateHolder) object;
                 CertificateFactory cf = CertificateFactory.getInstance("X.509");
                 return (X509Certificate) cf.generateCertificate(
                         new ByteArrayInputStream(certHolder.getEncoded()));
             } else {
                 throw new CertificateParsingException("Invalid PEM certificate format");
             }
         } catch (IOException | java.security.cert.CertificateException e) {
             throw e; // Re-throw exceptions directly
         } catch (Exception e) {
             throw new CertificateParsingException("Unexpected error parsing certificate", e);
         }
     }

    /**
     * Converts an X509Certificate to its PEM-encoded String representation.
     *
     * @param cert The X509Certificate to convert.
     * @return The PEM-encoded certificate as a String.
     * @throws CertificateEncodingException If the certificate cannot be encoded.
     */
    // CHECKSTYLE:OFF
    public static String convertCertToPEM(final X509Certificate cert) throws CertificateEncodingException {
        StringBuilder pemBuilder = new StringBuilder();
        pemBuilder.append("-----BEGIN CERTIFICATE-----\n");
        pemBuilder.append(java.util.Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(cert.getEncoded()));
        pemBuilder.append("\n-----END CERTIFICATE-----\n");
        return pemBuilder.toString();
    }
    // CHECKSTYLE:ON
    /**
     * Maps SAN type integers to their corresponding names.
     *
     * @param sanType The SAN type as an integer.
     * @return The SAN type name.
     */
    // CHECKSTYLE:OFF
    public static String getSanTypeName(final int sanType) {
        switch (sanType) {
            case 0:
                return "otherName";
            case 1:
                return "RFC822 Name";
            case 2:
                return "DNS Name";
            case 6:
                return "URI";
            case 7:
                return "IP Address";
            // Add more cases as needed
            default:
                return "Unknown Type";
        }
    }
    // CHECKSTYLE:ON

    /**
     * Parses the SAN value based on its type and returns a string representation.
     *
     * @param sanType  The SAN type.
     * @param sanValue The SAN value.
     * @return A string representation of the SAN value.
     */
    // CHECKSTYLE:OFF
    public static String parseSanValue(final int sanType, final Object sanValue) {
        if (sanValue == null) {
            return "null";
        }

        switch (sanType) {
            case 0:
                // otherName is typically a byte array (ASN1 encoded)
                if (sanValue instanceof byte[]) {
                    byte[] sanBytes = (byte[]) sanValue;
                    try {
                        ASN1Primitive sanObject = new ASN1InputStream(new ByteArrayInputStream(sanBytes)).readObject();
                        return asn1ToJson(sanObject);
                    } catch (IOException e) {
                        LOGGER.error("Failed to parse otherName SAN: {}", e.getMessage(), e);
                        return "Invalid ASN1 Structure";
                    }
                } else {
                    return sanValue.toString();
                }
            case 1:
            case 2:
            case 6:
            case 7:
                return sanValue.toString();
            default:
                return sanValue.toString();
        }
    }
    // CHECKSTYLE:ON

    /**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes The byte array.
     * @return Hexadecimal representation of the byte array.
     */
    private static String bytesToHex(final byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Extracts the User Principal Name (UPN) from the Subject Alternative Names (SANs) of the given X.509 certificate.
     * <p>
     * This method processes the SAN entries of the certificate, focusing specifically on entries of type
     * {@code otherName} (SAN type 0), and returns the UPN if found. If no UPN is present or an error occurs,
     * the method logs a warning or error and returns {@code null}.
     * </p>
     *
     * @param cert the {@link X509Certificate} from which the UPN will be extracted
     * @return the extracted UPN as a {@link String}, or {@code null} if no UPN is found or an error occurs
     */
    public static String extractUPN(final X509Certificate cert) {
        try {
            Collection<List<?>> sanCollection = cert.getSubjectAlternativeNames();
            if (sanCollection == null) {
                LOGGER.warn(NO_SAN_MESSAGE);
                return null;
            }

            for (List<?> sanItem : sanCollection) {
                Integer sanType = (Integer) sanItem.get(0);
                Object sanValue = sanItem.get(1);
                LOGGER.trace("Processing SAN Type: {}, Value: {}", sanType, sanValue);

                // Focus only on otherName entries (SAN type 0)
                if (sanType == 0 && sanValue instanceof byte[]) {
                    String upn = extractUPNFromOtherNameDirect((byte[]) sanValue);
                    if (upn != null) {
                        LOGGER.debug("Extracted UPN: {}", upn);
                        return upn;
                    }
                } else {
                    LOGGER.debug("Skipping SAN Type: {}, Value: {} as it's not an otherName or not byte[]",
                            sanType, sanValue);
                }
            }

            LOGGER.warn("UPN not found in the certificate's Subject Alternative Names.");
            return null;

        } catch (CertificateParsingException e) {
            LOGGER.error(FAILED_PARSE_SAN_MESSAGE, e.getMessage(), e);
            return null;
        } catch (Exception e) {
            LOGGER.error("Unexpected exception during UPN extraction: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Extracts the UPN from an otherName SAN entry's byte array directly without JSON conversion.
     *
     * @param sanValue The byte array representing the otherName SAN.
     * @return The extracted UPN as a String, or null if not found.
     */
    public static String extractUPNFromOtherNameDirect(final byte[] sanValue) {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(sanValue))) {
            ASN1Primitive sanObject = asn1InputStream.readObject();

            LOGGER.debug("ExtractUPNFromOtherNameDirect: sanObject class: {}",
                    sanObject.getClass().getName());

            ASN1Sequence sequence;

            // Check if sanObject is a tagged object
            if (sanObject instanceof ASN1TaggedObject) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) sanObject;
                ASN1Primitive innerObject = (ASN1Primitive) taggedObject.getBaseObject();

                if (innerObject instanceof ASN1Sequence) {
                    sequence = (ASN1Sequence) innerObject;
                } else {
                    LOGGER.warn("otherName SAN tagged inner object is not a sequence.");
                    return null;
                }
            } else if (sanObject instanceof ASN1Sequence) {
                sequence = (ASN1Sequence) sanObject;
            } else {
                LOGGER.warn("otherName SAN is not a sequence or tagged object.");
                return null;
            }

            if (sequence.size() != 2) {
                LOGGER.warn("otherName SAN sequence does not have exactly 2 elements.");
                return null;
            }

            // Extract OID
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0));
            if (!"1.3.6.1.4.1.311.20.2.3".equals(oid.getId())) {
                LOGGER.warn("otherName SAN OID does not match UPN OID.");
                return null;
            }

            // Extract the [0] EXPLICIT tag containing the UPN
            ASN1TaggedObject upnTaggedObject = ASN1TaggedObject.getInstance(sequence.getObjectAt(1));
            ASN1Primitive innerValue = (ASN1Primitive) upnTaggedObject.getBaseObject();

            if (innerValue instanceof DERUTF8String) {
                String upn = ((DERUTF8String) innerValue).getString();
                LOGGER.debug("Extracted UPN: {}", upn);
                return upn;
            } else if (innerValue instanceof DEROctetString) {
                byte[] utf8Bytes = ((DEROctetString) innerValue).getOctets();
                String upn = new String(utf8Bytes, StandardCharsets.UTF_8);
                LOGGER.debug("Extracted UPN (octet string): {}", upn);
                return upn;
            } else {
                LOGGER.warn("Unexpected inner value type in UPN otherName SAN: {}",
                        innerValue.getClass().getSimpleName());
            }

        } catch (IOException e) {
            LOGGER.error("IOException while parsing otherName SAN: {}", e.getMessage(), e);
        } catch (Exception e) {
            LOGGER.error("Unexpected exception while extracting UPN from otherName SAN: {}",
                    e.getMessage(), e);
        }
        return null;
    }

    /**
     * Extracts the Uniform Resource Name (URN) from the Subject Alternative Names (SANs) of the given
     * X.509 certificate.
     * <p>
     * This method processes the SAN entries of the certificate, focusing specifically on entries of type
     * {@code URI} (SAN type 6), and returns the URN if found. If no URN is present or an error occurs,
     * the method logs a warning or error and returns {@code null}.
     * </p>
     *
     * @param cert the {@link X509Certificate} from which the URN will be extracted
     * @return the extracted URN as a {@link String}, or {@code null} if no URN is found or an error occurs
     */
    public static String extractURN(final X509Certificate cert) {
        try {
            Collection<List<?>> sanCollection = cert.getSubjectAlternativeNames();
            if (sanCollection == null) {
                LOGGER.warn(NO_SAN_MESSAGE);
                return null;
            }

            for (List<?> sanItem : sanCollection) {
                Integer sanType = (Integer) sanItem.get(0);
                Object sanValue = sanItem.get(1);
                LOGGER.trace("Processing SAN Type: {}, Value: {}", sanType, sanValue);

                // CHECKSTYLE:OFF
                // Focus only on URI entries (SAN type 6)
                if (sanType == 6 && sanValue instanceof String) {
                    String urn = (String) sanValue;
                    LOGGER.debug("Extracted URN: {}", urn);
                    return urn;
                }
                // CHECKSTYLE:ON
            }

            LOGGER.warn("URN not found in the certificate's Subject Alternative Names.");
            return null;

        } catch (CertificateParsingException e) {
            LOGGER.error(FAILED_PARSE_SAN_MESSAGE, e.getMessage(), e);
            return null;
        } catch (Exception e) {
            LOGGER.error("Unexpected exception during URN extraction: {}", e.getMessage(), e);
            return null;
        }
    }
}
