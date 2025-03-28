package dod.p1.keycloak.utils;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.truststore.TruststoreProvider;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test class for OCSPUtils. This version uses JUnit 5 and Mockito,
 * and covers various scenarios for OCSP check, truststore lookup,
 * and certificate chain retrieval.
 */
class OCSPUtilsTest {

    private KeycloakSession keycloakSession;
    private HttpRequest httpRequest;
    private X509ClientCertificateLookup x509ClientCertificateLookup;
    private RealmModel realmModel;
    private TruststoreProvider truststoreProvider;
    private KeyStore keyStore;

    private X509Certificate certificate;
    private X509Certificate[] mockedCertificates;
    private X500Principal issuerPrincipal;
    private String expectedSerialNumber;
    private Map<X500Principal, X509Certificate> rootCerts;

    @BeforeEach
    void setup() throws Exception {
        keycloakSession = mock(KeycloakSession.class);
        httpRequest = mock(HttpRequest.class);
        x509ClientCertificateLookup = mock(X509ClientCertificateLookup.class);
        realmModel = mock(RealmModel.class);
        truststoreProvider = mock(TruststoreProvider.class);
        keyStore = mock(KeyStore.class);

        // Build a test certificate (using your utility method)
        certificate = Utils.buildTestCertificate();

        issuerPrincipal = new X500Principal("CN=Test, OU=ExampleOrg");
        rootCerts = Map.of(issuerPrincipal, certificate);

        mockedCertificates = new X509Certificate[]{certificate};
        expectedSerialNumber = "1234567890987654321"; // adjust this value as needed
    }

    @Test
    void testPerformOCSPCheck() throws GeneralSecurityException {
        String noCertProvided = "No certificates provided";

        // 1) Null certificate chain should return proper failure message.
        OCSPUtils.OCSPResult result = OCSPUtils.performOCSPCheck(keycloakSession, null);
        assertEquals(noCertProvided, result.getFailureReason());
        assertFalse(result.isOCSPGood());

        // 2) Empty certificate chain
        result = OCSPUtils.performOCSPCheck(keycloakSession, new X509Certificate[]{});
        assertEquals(noCertProvided, result.getFailureReason());
        assertFalse(result.isOCSPGood());

        // 3) Additional scenarios (e.g. valid chain) could be added here.
        // For example, if you have a known valid chain, you could verify a GOOD OCSPResult.
    }

    @Test
    void testFindCAInTruststore() throws GeneralSecurityException {
        // 1) When TruststoreProvider is null.
        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(null);
        assertNull(OCSPUtils.findCAInTruststore(keycloakSession, issuerPrincipal, expectedSerialNumber));

        // 2) When truststore is null.
        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);
        when(truststoreProvider.getTruststore()).thenReturn(null);
        assertNull(OCSPUtils.findCAInTruststore(keycloakSession, issuerPrincipal, expectedSerialNumber));

        // 3) When truststore is not null but CA lookup fails.
        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        // (Assuming that without setting root/intermediate maps the lookup returns null)
        assertNull(OCSPUtils.findCAInTruststore(keycloakSession, issuerPrincipal, expectedSerialNumber));

        // Optionally, to test the positive scenario, you could mock:
        // when(truststoreProvider.getRootCertificates()).thenReturn(Map.of(issuerPrincipal, List.of(certificate)));
        // Then assert that findCAInTruststore(...) returns a non-null certificate.
    }

    @Test
    void testExtractCommonName() {
        String unknown = "Unknown";
        String noCN = "nothing to see here";
        String wrongCNLocation = "something CN=, something, else";
        String goodCNSubject = "CN=q bonito baila Zac, AB= something";
        String expectedCN = "q bonito baila Zac";

        // 1) Null subjectDN returns "Unknown"
        assertEquals(unknown, OCSPUtils.extractCommonName(null));

        // 2) Subject without "CN=" returns "Unknown"
        assertEquals(unknown, OCSPUtils.extractCommonName(noCN));

        // 3) "CN=" present but no actual name returns "Unknown"
        assertEquals(unknown, OCSPUtils.extractCommonName(wrongCNLocation));

        // 4) Proper CN is extracted correctly.
        assertEquals(expectedCN, OCSPUtils.extractCommonName(goodCNSubject));
    }

    @Test
    void testOCSPResult() {
        boolean isOCSPGood = true;
        String failureReason = "everything is good";

        OCSPUtils.OCSPResult ocspResult = new OCSPUtils.OCSPResult(isOCSPGood, failureReason);
        assertTrue(ocspResult.isOCSPGood());
        assertEquals(failureReason, ocspResult.getFailureReason());
    }

    @Test
    void testGetCertificateChain1() throws GeneralSecurityException {
        RequiredActionContext requiredActionContext = mock(RequiredActionContext.class);
        when(requiredActionContext.getSession()).thenReturn(keycloakSession);
        when(requiredActionContext.getHttpRequest()).thenReturn(httpRequest);

        // 1) When provider is null.
        assertArrayEquals(new X509Certificate[0], OCSPUtils.getCertificateChain(requiredActionContext));

        // 2) When provider is available but returns a null chain.
        when(keycloakSession.getProvider(X509ClientCertificateLookup.class)).thenReturn(x509ClientCertificateLookup);
        assertArrayEquals(new X509Certificate[0], OCSPUtils.getCertificateChain(requiredActionContext));

        // 3) When chain is empty.
        when(x509ClientCertificateLookup.getCertificateChain(any(HttpRequest.class)))
                .thenReturn(new X509Certificate[]{});
        assertArrayEquals(new X509Certificate[0], OCSPUtils.getCertificateChain(requiredActionContext));

        // 4) When chain is provided.
        when(x509ClientCertificateLookup.getCertificateChain(any(HttpRequest.class)))
                .thenReturn(mockedCertificates);
        assertArrayEquals(mockedCertificates, OCSPUtils.getCertificateChain(requiredActionContext));

        // 5) When a GeneralSecurityException is thrown.
        when(x509ClientCertificateLookup.getCertificateChain(any(HttpRequest.class)))
                .thenThrow(GeneralSecurityException.class);
        assertArrayEquals(new X509Certificate[0], OCSPUtils.getCertificateChain(requiredActionContext));
    }

    @Test
    void testGetCertificateChain2() throws GeneralSecurityException {
        AuthenticationFlowContext authenticationFlowContext = mock(AuthenticationFlowContext.class);
        when(authenticationFlowContext.getSession()).thenReturn(keycloakSession);
        when(authenticationFlowContext.getHttpRequest()).thenReturn(httpRequest);

        // 1) Provider is null.
        assertArrayEquals(new X509Certificate[0], OCSPUtils.getCertificateChain(authenticationFlowContext));

        // 2) Chain is null.
        when(keycloakSession.getProvider(X509ClientCertificateLookup.class)).thenReturn(x509ClientCertificateLookup);
        assertArrayEquals(new X509Certificate[0], OCSPUtils.getCertificateChain(authenticationFlowContext));

        // 3) Chain is empty.
        when(x509ClientCertificateLookup.getCertificateChain(any(HttpRequest.class)))
                .thenReturn(new X509Certificate[]{});
        assertArrayEquals(new X509Certificate[0], OCSPUtils.getCertificateChain(authenticationFlowContext));

        // 4) Valid chain provided.
        when(x509ClientCertificateLookup.getCertificateChain(any(HttpRequest.class)))
                .thenReturn(mockedCertificates);
        assertArrayEquals(mockedCertificates, OCSPUtils.getCertificateChain(authenticationFlowContext));

        // 5) GeneralSecurityException scenario.
        when(x509ClientCertificateLookup.getCertificateChain(any(HttpRequest.class)))
                .thenThrow(GeneralSecurityException.class);
        assertArrayEquals(new X509Certificate[0], OCSPUtils.getCertificateChain(authenticationFlowContext));
    }
}
