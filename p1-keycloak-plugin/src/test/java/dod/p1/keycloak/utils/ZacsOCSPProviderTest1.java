package dod.p1.keycloak.utils;

import dod.p1.keycloak.utils.TestCertificateGenerator;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.def.BCOCSPProvider;
import org.keycloak.models.KeycloakSession;
import org.mockito.MockedStatic;
import sun.misc.Unsafe;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class ZacsOCSPProviderTest1 {

    // Static Config mock for tests.
    private static MockedStatic<Config> STATIC_CONFIG_MOCK;
    static {
        Config.Scope defaultScope = new Config.Scope() {
            public String get(String key) { return ""; }
            @Override public String get(String key, String defaultValue) { return ""; }
            @Override public String[] getArray(String key) { return new String[0]; }
            @Override public Boolean getBoolean(String key) { return false; }
            @Override public Boolean getBoolean(String key, Boolean defaultValue) { return defaultValue; }
            @Override public Integer getInt(String key) { return 0; }
            @Override public Integer getInt(String key, Integer defaultValue) { return defaultValue; }
            @Override public Long getLong(String key) { return 0L; }
            @Override public Long getLong(String key, Long defaultValue) { return defaultValue; }
            @Override public java.util.Set<String> getPropertyNames() { return java.util.Collections.emptySet(); }
            @Override public Config.Scope scope(String... names) { return this; }
        };
        STATIC_CONFIG_MOCK = mockStatic(Config.class);
        STATIC_CONFIG_MOCK.when(() -> Config.scope("babyYodaOcsp")).thenReturn(defaultScope);
    }

    private KeycloakSession session;
    private X509Certificate cert;
    private X509Certificate issuerCertificate;
    private List<URI> respondersURIs;

    @BeforeEach
    void setup() throws Exception {
        session = mock(KeycloakSession.class);
        // Use a self-signed certificate for tests that don't need full processing.
        cert = TestCertificateGenerator.generateSelfSignedCertificate();
        issuerCertificate = cert; // self-signed for simplicity
        URI uri = new URI("https://responder.example.com:8080");
        respondersURIs = List.of(uri);
    }

    @AfterAll
    static void tearDownAll() {
        STATIC_CONFIG_MOCK.close();
    }

    @Test
    void testCheckInvalidResponseObject() throws Exception {
        // Generate distinct certificates to force full processing.
        X509Certificate subjectCert = TestCertificateGenerator.generateSelfSignedCertificate();
        X509Certificate issuerCert = TestCertificateGenerator.generateSelfSignedCertificate();

        ZacsOCSPProvider provider = new ZacsOCSPProvider(List.of()) {
            @Override
            protected OCSPResp getResponse(KeycloakSession session, OCSPReq req, URI responderUri) {
                OCSPResp resp = mock(OCSPResp.class);
                try {
                    when(resp.getEncoded()).thenReturn(new byte[]{0x01});
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                try {
                    // Return an object that is not a BasicOCSPResp.
                    when(resp.getResponseObject()).thenReturn(new Object());
                } catch (org.bouncycastle.cert.ocsp.OCSPException e) {
                    throw new RuntimeException(e);
                }
                return resp;
            }
        };

        try {
            provider.check(session, subjectCert, issuerCert, respondersURIs, null, new Date());
            fail("Expected CertPathValidatorException not thrown");
        } catch (CertPathValidatorException e) {
            String msg = e.getMessage();
            assertTrue(msg.contains("Invalid OCSP response") || msg.contains("OCSP check failed"),
                    "Unexpected exception message: " + msg);
        }
    }

    @Test
    void testCheckExtractionFailure() throws Exception {
        // Generate distinct certificates.
        X509Certificate subjectCert = TestCertificateGenerator.generateSelfSignedCertificate();
        X509Certificate issuerCert = TestCertificateGenerator.generateSelfSignedCertificate();

        ZacsOCSPProvider provider = new ZacsOCSPProvider(List.of()) {
            @Override
            protected OCSPResp getResponse(KeycloakSession session, OCSPReq req, URI responderUri) {
                OCSPResp resp = mock(OCSPResp.class);
                BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
                try {
                    when(resp.getEncoded()).thenReturn(new byte[]{0x01, 0x02});
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                try {
                    when(resp.getResponseObject()).thenReturn(basicResp);
                } catch (org.bouncycastle.cert.ocsp.OCSPException e) {
                    throw new RuntimeException(e);
                }
                when(resp.getStatus()).thenReturn(0);
                SingleResp singleResp = mock(SingleResp.class);
                when(basicResp.getResponses()).thenReturn(new SingleResp[]{singleResp});
                return resp;
            }
            @Override
            protected X509Certificate extractResponderCert(BasicOCSPResp basicResp, X509Certificate issuerCertificate) {
                // Simulate extraction failure by returning null.
                return null;
            }
        };

        try {
            provider.check(session, subjectCert, issuerCert, respondersURIs, null, new Date());
            fail("Expected CertPathValidatorException not thrown");
        } catch (CertPathValidatorException e) {
            String msg = e.getMessage();
            assertTrue(msg.contains("Unable to extract responder certificate") || msg.contains("OCSP check failed"),
                    "Expected extraction failure message not found: " + msg);
        }
    }

    @Test
    void testCheckResponderIgnored() throws Exception {
        // Stub session.getProvider(HttpClientProvider.class) and its getHttpClient() to avoid NPE.
        HttpClientProvider dummyHttpClientProvider = mock(HttpClientProvider.class);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(dummyHttpClientProvider);
        CloseableHttpClient dummyHttpClient = mock(CloseableHttpClient.class);
        when(dummyHttpClientProvider.getHttpClient()).thenReturn(dummyHttpClient);

        try {
            ZacsOCSPProvider provider = new ZacsOCSPProvider(List.of("responder.example.com"));
            // With the responder in the ignored list, check() should bypass the real OCSP call and return GOOD.
            BCOCSPProvider.OCSPRevocationStatus status =
                    provider.check(session, cert, issuerCertificate, respondersURIs, null, new Date());
            assertNotNull(status);
            assertEquals(BCOCSPProvider.RevocationStatus.GOOD, status.getRevocationStatus());
        } catch (Exception e) {
            fail("Did not expect an exception when responder is ignored: " + e.getMessage());
        }
    }

    @Test
    void testGetResponderURIsPublicAdditional() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        // Use a certificate from Utils.buildTestCertificate() that is known to contain the AIA extension.
        X509Certificate aiaCert = Utils.buildTestCertificate();
        List<String> uris = provider.getResponderURIsPublic(aiaCert);
        assertNotNull(uris, "Responder URIs should not be null");
        assertFalse(uris.isEmpty(), "Responder URIs should not be empty");
        assertEquals("http://ocsp.entrust.net", uris.get(0));
    }

    private Unsafe getUnsafe() throws Exception {
        Field f = Unsafe.class.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        return (Unsafe) f.get(null);
    }
}
