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
import org.keycloak.http.HttpRequest;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.RequiredActionContext;
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertPathValidatorException;

import java.net.URI;

import java.util.stream.Stream;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static dod.p1.keycloak.common.CommonConfig.getInstance;

public final class X509Tools {

    /** The LOGGER. */
    private static final Logger LOGGER = LogManager.getLogger(X509Tools.class);

    /** The certificate policy OID. */
    private static final String CERTIFICATE_POLICY_OID = "2.5.29.32";

    /** The max number of certificate policies to check. */
    private static final int MAX_CERT_POLICIES_TO_CHECK = 10;

    // Sonarqube critical fix
    /** Get x509 identity. */
    private static final String GET_X509_IDENTITY = "GET_X509_IDENTITY";

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
                    CommonConfig.getInstance(session, realm).getUserIdentityAttribute(), username);
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
     * Get x509 user name from identity.
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
     * Get x509 user name from required action context.
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
            final AuthenticationSessionModel authenticationSession) throws CertPathValidatorException {

        String logPrefix = getLogPrefix(authenticationSession, "GET_X509_IDENTITY_FROM_CHAIN");

        if (certs == null || certs.length == 0) {
            LOGGER.info("{} no valid certs found", logPrefix);
            return null;
        }

        // Extract issuer certificate from the certificate chain
        X509Certificate issuerCertificate = certs.length > 1 ? certs[1] : null;

        try {
            ZacsOCSPProvider ocspProvider = new ZacsOCSPProvider();
            List<String> responderURIs = ocspProvider.getResponderURIsPublic(certs[0]);
            List<URI> responderURIsAsURI = responderURIs.stream()
                    .map(URI::create)
                    .collect(Collectors.toList());
            X509Certificate responderCert = null;
            Date date = null;
            LOGGER.debug("{}: ZacsOCSPProvider - cert: {} issuer: {} responderURI: {}",
                    getLogPrefix(authenticationSession, GET_X509_IDENTITY),
                    certs[0],
                    issuerCertificate,
                    responderURIsAsURI.get(0)
            );

            // Perform OCSP check
            BCOCSPProvider.OCSPRevocationStatus ocspStatus = ocspProvider.check(
                    session,
                    certs[0],  // Assuming certs[0] represents the certificate for which the OCSP check is performed
                    issuerCertificate,
                    responderURIsAsURI.get(0),
                    responderCert,  // Setting to null if not needed
                    date  // Setting to null if not needed
            );
            // Check the OCSP revocation status
            if (ocspStatus.getRevocationStatus() != OCSPProvider.RevocationStatus.GOOD) {
                LOGGER.warn("{}: ZacsOCSPProvider check failed",
                        getLogPrefix(authenticationSession, GET_X509_IDENTITY));
                return null;
            } else {
                LOGGER.debug("{}: ZacsOCSPProvider check passed",
                        getLogPrefix(authenticationSession, GET_X509_IDENTITY));
            }
        } catch (CertificateEncodingException e) {
            LOGGER.warn("{} Error while getting responder URIs from certificate: {}",
                    logPrefix, e.getMessage());
            return null;
        }

        boolean hasValidPolicy = false;

        int index = 0;
        // Only check up to 10 cert policies, DoD only uses 1-2 policies
        while (!hasValidPolicy && index < MAX_CERT_POLICIES_TO_CHECK) {
            try {
                String certificatePolicyId = getCertificatePolicyId(certs[0], index, 0);
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

}
