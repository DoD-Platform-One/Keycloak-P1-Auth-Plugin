package dod.p1.keycloak.utils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.crypto.def.BCOCSPProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.truststore.TruststoreProvider;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import sun.misc.Unsafe;

/**
 * Extended tests for OCSPUtils to increase code coverage.
 */
public class OCSPUtilsTest2 {

    // Set up a static Config mock as in your reference.
    private static MockedStatic<Config> STATIC_CONFIG_MOCK;
    static {
        Config.Scope defaultScope = new Config.Scope() {
            @Override
            public String get(String key) {
                return "";
            }
            @Override
            public String get(String key, String defaultValue) {
                return "";
            }
            @Override
            public String[] getArray(String key) {
                return new String[0];
            }
            @Override
            public Boolean getBoolean(String key) {
                return false;
            }
            @Override
            public Boolean getBoolean(String key, Boolean defaultValue) {
                return defaultValue;
            }
            @Override
            public Integer getInt(String key) {
                return 0;
            }
            @Override
            public Integer getInt(String key, Integer defaultValue) {
                return defaultValue;
            }
            @Override
            public Long getLong(String key) {
                return 0L;
            }
            @Override
            public Long getLong(String key, Long defaultValue) {
                return defaultValue;
            }
            @Override
            public java.util.Set<String> getPropertyNames() {
                return java.util.Collections.emptySet();
            }
            @Override
            public Config.Scope scope(String... names) {
                return this;
            }
        };
        STATIC_CONFIG_MOCK = Mockito.mockStatic(Config.class);
        STATIC_CONFIG_MOCK.when(() -> Config.scope("babyYodaOcsp")).thenReturn(defaultScope);
    }

    @AfterAll
    static void tearDownAll() {
        STATIC_CONFIG_MOCK.close();
    }

    /**
     * Dummy OCSP provider that extends ZacsOCSPProvider to simulate OCSP behavior.
     */
    class DummyOCSPProvider extends ZacsOCSPProvider {
        private final List<String> responderURIs;
        private final BCOCSPProvider.OCSPRevocationStatus ocspStatus;

        public DummyOCSPProvider(List<String> responderURIs, BCOCSPProvider.OCSPRevocationStatus ocspStatus) {
            this.responderURIs = responderURIs;
            this.ocspStatus = ocspStatus;
        }

        public List<String> getResponderURIsPublic(X509Certificate cert) throws CertificateEncodingException {
            return responderURIs;
        }

        public BCOCSPProvider.OCSPRevocationStatus check(KeycloakSession session, X509Certificate eeCert,
                                                         X509Certificate issuerCert, List<URI> responderURIs,
                                                         Object unused1, Object unused2) {
            return ocspStatus;
        }
    }

    private KeycloakSession keycloakSession;
    private RealmModel realmModel;
    private TruststoreProvider truststoreProvider;
    private KeyStore keyStore;
    private X500Principal issuerPrincipal;
    private String expectedSerialNumber;
    private X509Certificate endEntityCert;
    private X509Certificate issuerCert;

    @BeforeEach
    public void setup() throws Exception {
        keycloakSession = mock(KeycloakSession.class);
        realmModel = mock(RealmModel.class);
        truststoreProvider = mock(TruststoreProvider.class);
        keyStore = mock(KeyStore.class);
        issuerPrincipal = new X500Principal("CN=TestCA, OU=ExampleOrg");
        expectedSerialNumber = "1234567890987654321";

        // Create dummy end-entity and issuer certificate mocks.
        endEntityCert = mock(X509Certificate.class);
        issuerCert = mock(X509Certificate.class);

        when(endEntityCert.getIssuerX500Principal()).thenReturn(issuerPrincipal);
        when(endEntityCert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=EndEntity, OU=ExampleOrg"));
        when(issuerCert.getSubjectX500Principal()).thenReturn(issuerPrincipal);
        doNothing().when(issuerCert).checkValidity();
        // Stub the serial number to avoid NPEs in OCSPUtils.getIssuerCertificate().
        when(issuerCert.getSerialNumber()).thenReturn(new BigInteger(expectedSerialNumber));
        when(endEntityCert.getSerialNumber()).thenReturn(new BigInteger("9876543210"));
        when(endEntityCert.getNotAfter()).thenReturn(new java.util.Date());
    }

    //////////// Tests for performOCSPCheck ////////////

    @Test
    public void testPerformOCSPCheck_NoTrustedCA() throws GeneralSecurityException {
        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);
        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        when(truststoreProvider.getRootCertificates()).thenReturn(Collections.emptyMap());
        when(truststoreProvider.getIntermediateCertificates()).thenReturn(Collections.emptyMap());

        X509Certificate[] certChain = new X509Certificate[]{endEntityCert};

        OCSPUtils.OCSPResult result = OCSPUtils.performOCSPCheck(keycloakSession, certChain);
        assertFalse(result.isOCSPGood());
        assertEquals("No trusted CA found", result.getFailureReason());
    }

    @Test
    public void testPerformOCSPCheck_NoResponderURIs() throws GeneralSecurityException {
        X509Certificate[] certChain = new X509Certificate[]{endEntityCert, issuerCert};

        // Prepare truststore so that issuerCert is found.
        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);
        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        Map<X500Principal, List<X509Certificate>> rootMap = Map.of(issuerPrincipal, List.of(issuerCert));
        when(truststoreProvider.getRootCertificates()).thenReturn(rootMap);
        when(truststoreProvider.getIntermediateCertificates()).thenReturn(Collections.emptyMap());

        try (MockedConstruction<ZacsOCSPProvider> mocked = Mockito.mockConstruction(ZacsOCSPProvider.class,
                (mock, context) -> {
                    when(mock.getResponderURIsPublic(any())).thenReturn(Collections.emptyList());
                })) {
            OCSPUtils.OCSPResult result = OCSPUtils.performOCSPCheck(keycloakSession, certChain);
            assertFalse(result.isOCSPGood());
            assertEquals("No responder URIs found", result.getFailureReason());
        }
    }

    @Test
    public void testPerformOCSPCheck_OCSPPass() throws GeneralSecurityException {
        X509Certificate[] certChain = new X509Certificate[]{endEntityCert, issuerCert};

        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);
        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        Map<X500Principal, List<X509Certificate>> rootMap = Map.of(issuerPrincipal, List.of(issuerCert));
        when(truststoreProvider.getRootCertificates()).thenReturn(rootMap);
        when(truststoreProvider.getIntermediateCertificates()).thenReturn(Collections.emptyMap());

        BCOCSPProvider.OCSPRevocationStatus goodStatus = mock(BCOCSPProvider.OCSPRevocationStatus.class);
        when(goodStatus.getRevocationStatus()).thenReturn(BCOCSPProvider.RevocationStatus.GOOD);

        try (MockedConstruction<ZacsOCSPProvider> mocked = Mockito.mockConstruction(ZacsOCSPProvider.class,
                (mock, context) -> {
                    when(mock.getResponderURIsPublic(any())).thenReturn(List.of("http://ocsp.responder/test"));
                    // Disambiguate the overloaded check method.
                    when(mock.check(
                            any(KeycloakSession.class),
                            any(X509Certificate.class),
                            any(X509Certificate.class),
                            (List<URI>) any(),
                            any(),
                            any()
                    )).thenReturn(goodStatus);
                })) {
            OCSPUtils.OCSPResult result = OCSPUtils.performOCSPCheck(keycloakSession, certChain);
            assertTrue(result.isOCSPGood());
            assertNull(result.getFailureReason());
        }
    }

    @Test
    public void testPerformOCSPCheck_OCSPFail() throws GeneralSecurityException {
        X509Certificate[] certChain = new X509Certificate[]{endEntityCert, issuerCert};

        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);
        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        Map<X500Principal, List<X509Certificate>> rootMap = Map.of(issuerPrincipal, List.of(issuerCert));
        when(truststoreProvider.getRootCertificates()).thenReturn(rootMap);
        when(truststoreProvider.getIntermediateCertificates()).thenReturn(Collections.emptyMap());

        BCOCSPProvider.OCSPRevocationStatus failStatus = mock(BCOCSPProvider.OCSPRevocationStatus.class);
        when(failStatus.getRevocationStatus()).thenReturn(BCOCSPProvider.RevocationStatus.REVOKED);

        try (MockedConstruction<ZacsOCSPProvider> mocked = Mockito.mockConstruction(ZacsOCSPProvider.class,
                (mock, context) -> {
                    when(mock.getResponderURIsPublic(any())).thenReturn(List.of("http://ocsp.responder/test"));
                    when(mock.check(
                            any(KeycloakSession.class),
                            any(X509Certificate.class),
                            any(X509Certificate.class),
                            (List<URI>) any(),
                            any(),
                            any()
                    )).thenReturn(failStatus);
                })) {
            OCSPUtils.OCSPResult result = OCSPUtils.performOCSPCheck(keycloakSession, certChain);
            assertFalse(result.isOCSPGood());
            assertEquals("OCSP status: " + BCOCSPProvider.RevocationStatus.REVOKED, result.getFailureReason());
        }
    }

    @Test
    public void testPerformOCSPCheck_CertificateEncodingException() throws GeneralSecurityException {
        X509Certificate[] certChain = new X509Certificate[]{endEntityCert, issuerCert};

        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);
        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        Map<X500Principal, List<X509Certificate>> rootMap = Map.of(issuerPrincipal, List.of(issuerCert));
        when(truststoreProvider.getRootCertificates()).thenReturn(rootMap);
        when(truststoreProvider.getIntermediateCertificates()).thenReturn(Collections.emptyMap());

        try (MockedConstruction<ZacsOCSPProvider> mocked = Mockito.mockConstruction(ZacsOCSPProvider.class,
                (mock, context) -> {
                    when(mock.getResponderURIsPublic(any())).thenThrow(new CertificateEncodingException("Test encoding error"));
                })) {
            OCSPUtils.OCSPResult result = OCSPUtils.performOCSPCheck(keycloakSession, certChain);
            assertFalse(result.isOCSPGood());
            assertEquals("Certificate encoding error", result.getFailureReason());
        }
    }

    //////////// Tests for extractCommonName ////////////

    @Test
    public void testExtractCommonName_NullInput() {
        assertEquals("Unknown", OCSPUtils.extractCommonName(null));
    }

    @Test
    public void testExtractCommonName_NoCN() {
        String input = "OU=Test, O=Example";
        assertEquals("Unknown", OCSPUtils.extractCommonName(input));
    }

    @Test
    public void testExtractCommonName_WithCNAtStart() {
        String input = "CN=MyName, OU=Test, O=Example";
        assertEquals("MyName", OCSPUtils.extractCommonName(input));
    }

    @Test
    public void testExtractCommonName_WithCNInMiddle() {
        String input = "OU=Test, CN=MiddleName, O=Example";
        assertEquals("MiddleName", OCSPUtils.extractCommonName(input));
    }

    @Test
    public void testExtractCommonName_WithCNWithSpaces() {
        String input = "OU=Test, CN=  Spaced Name  , O=Example";
        // The method splits on commas and returns the substring after "CN=".
        // Expected value is "  Spaced Name" (without trailing space).
        assertEquals("  Spaced Name", OCSPUtils.extractCommonName(input));
    }

    //////////// Additional tests for findCAInTruststore ////////////

    @Test
    public void testFindCAInTruststore_PartialMatch_NullExpectedSerial() throws GeneralSecurityException {
        // When expectedSerialNumber is null, the method returns the first valid CA.
        X509Certificate caCert = mock(X509Certificate.class);
        when(caCert.getSubjectX500Principal()).thenReturn(issuerPrincipal);
        when(caCert.getSerialNumber()).thenReturn(new BigInteger("9999"));
        doNothing().when(caCert).checkValidity();

        Map<X500Principal, List<X509Certificate>> rootMap = Map.of(issuerPrincipal, List.of(caCert));
        Map<X500Principal, List<X509Certificate>> interMap = Map.of();

        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        when(truststoreProvider.getRootCertificates()).thenReturn(rootMap);
        when(truststoreProvider.getIntermediateCertificates()).thenReturn(interMap);
        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);

        X509Certificate result = OCSPUtils.findCAInTruststore(keycloakSession, issuerPrincipal, null);
        assertNotNull(result);
        assertEquals(caCert, result);
    }

    @Test
    public void testFindCAInTruststore_NoMatch() throws GeneralSecurityException {
        // If no certificate matches the issuer principal, the method returns null.
        X509Certificate caCert = mock(X509Certificate.class);
        when(caCert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=Other"));
        when(caCert.getSerialNumber()).thenReturn(new BigInteger("1111"));
        doNothing().when(caCert).checkValidity();

        Map<X500Principal, List<X509Certificate>> rootMap = Map.of(new X500Principal("CN=Other"), List.of(caCert));
        Map<X500Principal, List<X509Certificate>> interMap = Map.of();

        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        when(truststoreProvider.getRootCertificates()).thenReturn(rootMap);
        when(truststoreProvider.getIntermediateCertificates()).thenReturn(interMap);
        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);

        X509Certificate result = OCSPUtils.findCAInTruststore(keycloakSession, issuerPrincipal, expectedSerialNumber);
        assertNull(result);
    }
}
