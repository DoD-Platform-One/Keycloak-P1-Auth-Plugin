package dod.p1.keycloak.registration;

import dod.p1.keycloak.utils.ZacsOCSPProvider;
import org.keycloak.utils.OCSPProvider;
import org.keycloak.crypto.def.BCOCSPProvider;
import dod.p1.keycloak.common.CommonConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
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
import org.keycloak.truststore.TruststoreProvider;
import org.keycloak.Config;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.security.cert.CertificateEncodingException;
import javax.security.auth.x500.X500Principal;
import java.util.stream.Stream;
import java.util.stream.Collectors;

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

    private static String getLogPrefix(final AuthenticationSessionModel authenticationSession, final String suffix) {
        return "P1_X509_TOOLS_" + suffix + "_" + authenticationSession.getParentSession().getId();
    }

    // hide constructor per checkstyle linting
    private X509Tools() { }

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
     * Find CA In Truststore.
     * @param session a Keycloak Session
     * @param issuer a X500Principal
     * @return X509Certificate
     */
    public static X509Certificate findCAInTruststore(
            final KeycloakSession session,
            final X500Principal issuer) throws GeneralSecurityException {

        LOGGER.debug("ISSUER {}", issuer);
        LOGGER.debug("SESSION {}", session);

        TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
        LOGGER.info("TRUSTSTOREPROVIDER {}", truststoreProvider);

        if (truststoreProvider == null || truststoreProvider.getTruststore() == null) {
            return null;
        }
        Map<X500Principal, X509Certificate> rootCerts = truststoreProvider.getRootCertificates();
        X509Certificate ca = rootCerts.get(issuer);

        LOGGER.debug("ROOTCERTS {}", rootCerts);
        LOGGER.debug("CA {}", ca);

        if (ca == null) {
            // fallback to lookup the issuer from the list of intermediary CAs
            ca = truststoreProvider.getIntermediateCertificates().get(issuer);
            LOGGER.debug("GETISSUER {}", ca);
        }
        if (ca != null) {
            ca.checkValidity();
        }
        return ca;
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
        String ocspEnabled = Config.scope("babyYodaOcsp").get("enabled", "false");
        LOGGER.info("ZacsOCSPProvider Mode Set: {}", ocspEnabled);

        if (certs == null || certs.length == 0) {
          LOGGER.info("{} no valid certs found", logPrefix);
          return null;
        }

        X509Certificate cert = certs[0]; // simplifying the assignment; handle array checks as needed
        // OCSP Check to address revoked cert getting activecac attribute.
        //To Enable in command:  "--spi-baby-yoda-ocsp-enabled=true"
        //or in ENV:  KC_SPI_BABY_YODA_OCSP_ENABLED: "true"
        //KC_SPI_TRUSTSTORE_FILE_FILE: "/opt/keycloak/certs/truststore.jks"
        //KC_SPI_TRUSTSTORE_FILE_PASSWORD: "trust_pw"
        if  (ocspEnabled.equals("true")) { // Don't perform this check at all if bypass
          X509Certificate issuer = certs.length > 1 ? certs[1] : findCAInTruststore(session, cert
                      .getIssuerX500Principal());

          if (issuer == null) {
                  LOGGER.error("{} No trusted CA in certificate found: {}", logPrefix, cert.getIssuerX500Principal());
                  return null; // Stop processing since OCSP check is mandatory and CA is not trusted
          }

          try {
              ZacsOCSPProvider ocspProvider = new ZacsOCSPProvider();
              List<String> responderURIs = ocspProvider.getResponderURIsPublic(cert);
              List<URI> responderURIsAsURI = responderURIs.stream()
                      .map(URI::create).collect(Collectors.toList());

              LOGGER.debug("{}: ZacsOCSPProvider - cert: {} issuer: {} responderURI: {}",
                      logPrefix, cert, issuer, responderURIsAsURI.get(0)
              );

              // Perform OCSP check
              BCOCSPProvider.OCSPRevocationStatus ocspStatus = ocspProvider.check(
                      session, cert, issuer, responderURIsAsURI.get(0), null, null);
              // Check the OCSP revocation status
              if (ocspStatus.getRevocationStatus() != OCSPProvider.RevocationStatus.GOOD) {
                  LOGGER.warn("{}: ZacsOCSPProvider check failed", logPrefix);
                      return null; // Enforce mode: halt the process if OCSP check fails
              } else {
                  LOGGER.debug("{}: ZacsOCSPProvider check passed", logPrefix);
              }
          } catch (CertificateEncodingException e) {
              LOGGER.warn("{} Error while getting responder URIs from certificate: {}",
                      logPrefix, e.getMessage());
              return null;
          }
        }

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
                // abort checks
                index = MAX_CERT_POLICIES_TO_CHECK;
            }
        }

        if (!hasValidPolicy) {
            LOGGER.warn("{} no valid cert policies found", logPrefix);
            return null;
        }

        if (realm.getAuthenticatorConfigsStream().count() > 0) {
            return realm.getAuthenticatorConfigsStream().filter(config ->
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
}
