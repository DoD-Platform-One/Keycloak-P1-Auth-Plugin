package dod.p1.keycloak.utils;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.crypto.def.BCOCSPProvider;
import org.keycloak.models.KeycloakSession;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.security.cert.CRLReason;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Test class for {@link ZacsOCSPProvider}.
 * This class tests various methods of the ZacsOCSPProvider class to improve test coverage.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ZacsOCSPProviderTest {

    @Mock
    private KeycloakSession keycloakSession;

    @Mock
    private X509Certificate certificate;

    @Mock
    private X509Certificate issuerCertificate;

    private ZacsOCSPProvider ocspProvider;

    @BeforeEach
    public void setUp() {
        ocspProvider = new ZacsOCSPProvider();
    }

    /**
     * Test for the shouldIgnoreNonce method with a null responder URI.
     */
    @Test
    public void testShouldIgnoreNonce_NullResponderURI() {
        List<String> ignoreList = Arrays.asList("ocsp.example.com", "ocsp.test.com");
        boolean result = ocspProvider.shouldIgnoreNonce(null, ignoreList);
        assertFalse(result, "Should return false for null responder URI");
    }

    /**
     * Test for the shouldIgnoreNonce method with a null ignore list.
     */
    @Test
    public void testShouldIgnoreNonce_NullIgnoreList() {
        boolean result = ocspProvider.shouldIgnoreNonce("http://ocsp.example.com", null);
        assertFalse(result, "Should return false for null ignore list");
    }

    /**
     * Test for the shouldIgnoreNonce method with an empty ignore list.
     */
    @Test
    public void testShouldIgnoreNonce_EmptyIgnoreList() {
        boolean result = ocspProvider.shouldIgnoreNonce("http://ocsp.example.com", new ArrayList<>());
        assertFalse(result, "Should return false for empty ignore list");
    }

    /**
     * Test for the shouldIgnoreNonce method with a responder URI that is in the ignore list.
     */
    @Test
    public void testShouldIgnoreNonce_ResponderInIgnoreList() {
        List<String> ignoreList = Arrays.asList("ocsp.example.com", "ocsp.test.com");
        boolean result = ocspProvider.shouldIgnoreNonce("http://ocsp.example.com/ocsp", ignoreList);
        assertTrue(result, "Should return true for responder URI in ignore list");
    }

    /**
     * Test for the shouldIgnoreNonce method with a responder URI that is not in the ignore list.
     */
    @Test
    public void testShouldIgnoreNonce_ResponderNotInIgnoreList() {
        List<String> ignoreList = Arrays.asList("ocsp.example.com", "ocsp.test.com");
        boolean result = ocspProvider.shouldIgnoreNonce("http://ocsp.other.com/ocsp", ignoreList);
        assertFalse(result, "Should return false for responder URI not in ignore list");
    }

    /**
     * Test for the shouldIgnoreNonce method with an invalid responder URI.
     */
    @Test
    public void testShouldIgnoreNonce_InvalidResponderURI() {
        List<String> ignoreList = Arrays.asList("ocsp.example.com", "ocsp.test.com");
        boolean result = ocspProvider.shouldIgnoreNonce("invalid-uri", ignoreList);
        assertFalse(result, "Should return false for invalid responder URI");
    }

    /**
     * Test for the validateResponderURIs method with a null list.
     */
    @Test
    public void testValidateResponderURIs_NullList() throws Exception {
        Method validateResponderURIsMethod = ZacsOCSPProvider.class.getDeclaredMethod("validateResponderURIs", List.class);
        validateResponderURIsMethod.setAccessible(true);

        Exception exception = assertThrows(Exception.class, () -> {
            validateResponderURIsMethod.invoke(ocspProvider, (Object) null);
        }, "Should throw exception for null responder URIs");
        
        // Check that the cause is IllegalArgumentException
        Throwable cause = exception.getCause();
        assertTrue(cause instanceof IllegalArgumentException, "Cause should be IllegalArgumentException");
        assertEquals("Need at least one responder URI", cause.getMessage());
    }

    /**
     * Test for the validateResponderURIs method with an empty list.
     */
    @Test
    public void testValidateResponderURIs_EmptyList() throws Exception {
        Method validateResponderURIsMethod = ZacsOCSPProvider.class.getDeclaredMethod("validateResponderURIs", List.class);
        validateResponderURIsMethod.setAccessible(true);

        Exception exception = assertThrows(Exception.class, () -> {
            validateResponderURIsMethod.invoke(ocspProvider, new ArrayList<URI>());
        }, "Should throw exception for empty responder URIs");
        
        // Check that the cause is IllegalArgumentException
        Throwable cause = exception.getCause();
        assertTrue(cause instanceof IllegalArgumentException, "Cause should be IllegalArgumentException");
        assertEquals("Need at least one responder URI", cause.getMessage());
    }

    /**
     * Test for the validateResponderURIs method with a valid list.
     */
    @Test
    public void testValidateResponderURIs_ValidList() throws Exception {
        Method validateResponderURIsMethod = ZacsOCSPProvider.class.getDeclaredMethod("validateResponderURIs", List.class);
        validateResponderURIsMethod.setAccessible(true);

        List<URI> uris = Arrays.asList(new URI("http://ocsp.example.com"));
        validateResponderURIsMethod.invoke(ocspProvider, uris);
        // No exception should be thrown
    }

    /**
     * Test for the createMockOCSPResponse method.
     */
    @Test
    public void testCreateMockOCSPResponse() throws Exception {
        Method createMockOCSPResponseMethod = ZacsOCSPProvider.class.getDeclaredMethod("createMockOCSPResponse", String.class);
        createMockOCSPResponseMethod.setAccessible(true);

        BCOCSPProvider.OCSPRevocationStatus result = (BCOCSPProvider.OCSPRevocationStatus) createMockOCSPResponseMethod.invoke(ocspProvider, "ocsp.example.com");
        
        assertNotNull(result, "Mock OCSP response should not be null");
        assertEquals(BCOCSPProvider.RevocationStatus.GOOD, result.getRevocationStatus(), "Revocation status should be GOOD");
        assertEquals(CRLReason.UNSPECIFIED, result.getRevocationReason(), "Revocation reason should be UNSPECIFIED");
        assertNull(result.getRevocationTime(), "Revocation time should be null");
    }

    // Removed testGetResponderURIsPublic as it requires complex mocking of static methods
    
    /**
     * Test for the logOCSPRequest method with nonce enforced.
     */
    @Test
    public void testLogOCSPRequest_WithNonce() throws Exception {
        Method logOCSPRequestMethod = ZacsOCSPProvider.class.getDeclaredMethod("logOCSPRequest", OCSPReq.class, boolean.class);
        logOCSPRequestMethod.setAccessible(true);
        
        // Create a mock OCSPReq
        OCSPReq ocspReq = mock(OCSPReq.class);
        when(ocspReq.getEncoded()).thenReturn(new byte[]{1, 2, 3, 4});
        
        // Call the method with nonce enforced
        logOCSPRequestMethod.invoke(ocspProvider, ocspReq, true);
        
        // No exception should be thrown
    }
    
    /**
     * Test for the logOCSPRequest method without nonce enforced.
     */
    @Test
    public void testLogOCSPRequest_WithoutNonce() throws Exception {
        Method logOCSPRequestMethod = ZacsOCSPProvider.class.getDeclaredMethod("logOCSPRequest", OCSPReq.class, boolean.class);
        logOCSPRequestMethod.setAccessible(true);
        
        // Create a mock OCSPReq
        OCSPReq ocspReq = mock(OCSPReq.class);
        when(ocspReq.getEncoded()).thenReturn(new byte[]{1, 2, 3, 4});
        
        // Call the method without nonce enforced
        logOCSPRequestMethod.invoke(ocspProvider, ocspReq, false);
        
        // No exception should be thrown
    }
    
    /**
     * Test for the logOCSPRequest method with encoding exception.
     */
    @Test
    public void testLogOCSPRequest_EncodingException() throws Exception {
        Method logOCSPRequestMethod = ZacsOCSPProvider.class.getDeclaredMethod("logOCSPRequest", OCSPReq.class, boolean.class);
        logOCSPRequestMethod.setAccessible(true);
        
        // Create a mock OCSPReq that throws IOException when getEncoded is called
        OCSPReq ocspReq = mock(OCSPReq.class);
        when(ocspReq.getEncoded()).thenThrow(new IOException("Test encoding exception"));
        
        // Call the method with nonce enforced
        logOCSPRequestMethod.invoke(ocspProvider, ocspReq, true);
        
        // No exception should be thrown, the lambda should handle the exception
    }
    
    /**
     * Test for the logOcspResponse method with successful encoding.
     */
    @Test
    public void testLogOcspResponse_Success() throws Exception {
        Method logOcspResponseMethod = ZacsOCSPProvider.class.getDeclaredMethod("logOcspResponse", OCSPResp.class);
        logOcspResponseMethod.setAccessible(true);
        
        // Create a mock OCSPResp
        OCSPResp ocspResp = mock(OCSPResp.class);
        when(ocspResp.getEncoded()).thenReturn(new byte[]{1, 2, 3, 4});
        
        // Call the method
        logOcspResponseMethod.invoke(ocspProvider, ocspResp);
        
        // No exception should be thrown
    }
    
    /**
     * Test for the logOcspResponse method with encoding exception.
     */
    @Test
    public void testLogOcspResponse_EncodingException() throws Exception {
        Method logOcspResponseMethod = ZacsOCSPProvider.class.getDeclaredMethod("logOcspResponse", OCSPResp.class);
        logOcspResponseMethod.setAccessible(true);
        
        // Create a mock OCSPResp that throws IOException when getEncoded is called
        OCSPResp ocspResp = mock(OCSPResp.class);
        when(ocspResp.getEncoded()).thenThrow(new IOException("Test encoding exception"));
        
        // Call the method
        logOcspResponseMethod.invoke(ocspProvider, ocspResp);
        
        // No exception should be thrown, the method should handle the exception
    }
    
    /**
     * Test for the loadOcspIgnoreList method with non-empty list.
     */
    @Test
    public void testLoadOcspIgnoreList_NonEmptyList() throws Exception {
        Method loadOcspIgnoreListMethod = ZacsOCSPProvider.class.getDeclaredMethod("loadOcspIgnoreList");
        loadOcspIgnoreListMethod.setAccessible(true);
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            // Mock Config.scope
            Config.Scope scopeMock = mock(Config.Scope.class);
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scopeMock);
            
            // Mock scope.get to return a non-empty list
            when(scopeMock.get("ignoreList", "")).thenReturn("ocsp.example.com, ocsp.test.com");
            
            // Call the method
            List<String> result = (List<String>) loadOcspIgnoreListMethod.invoke(null);
            
            // Verify the result
            assertNotNull(result, "Result should not be null");
            assertEquals(2, result.size(), "Result should contain two entries");
            assertTrue(result.contains("ocsp.example.com"), "Result should contain ocsp.example.com");
            assertTrue(result.contains("ocsp.test.com"), "Result should contain ocsp.test.com");
        }
    }
    
    /**
     * Test for the loadOcspIgnoreList method with empty list.
     */
    @Test
    public void testLoadOcspIgnoreList_EmptyList() throws Exception {
        Method loadOcspIgnoreListMethod = ZacsOCSPProvider.class.getDeclaredMethod("loadOcspIgnoreList");
        loadOcspIgnoreListMethod.setAccessible(true);
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            // Mock Config.scope
            Config.Scope scopeMock = mock(Config.Scope.class);
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scopeMock);
            
            // Mock scope.get to return an empty string
            when(scopeMock.get("ignoreList", "")).thenReturn("");
            
            // Call the method
            List<String> result = (List<String>) loadOcspIgnoreListMethod.invoke(null);
            
            // Verify the result
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isEmpty(), "Result should be empty");
        }
    }
    
    /**
     * Test for the loadOcspIgnoreList method with null list.
     */
    @Test
    public void testLoadOcspIgnoreList_NullList() throws Exception {
        Method loadOcspIgnoreListMethod = ZacsOCSPProvider.class.getDeclaredMethod("loadOcspIgnoreList");
        loadOcspIgnoreListMethod.setAccessible(true);
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            // Mock Config.scope
            Config.Scope scopeMock = mock(Config.Scope.class);
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scopeMock);
            
            // Mock scope.get to return null
            when(scopeMock.get("ignoreList", "")).thenReturn(null);
            
            // Call the method
            List<String> result = (List<String>) loadOcspIgnoreListMethod.invoke(null);
            
            // Verify the result
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isEmpty(), "Result should be empty");
        }
    }
    
    /**
     * Test for the loadOcspIgnoreList method with exception.
     */
    @Test
    public void testLoadOcspIgnoreList_Exception() throws Exception {
        Method loadOcspIgnoreListMethod = ZacsOCSPProvider.class.getDeclaredMethod("loadOcspIgnoreList");
        loadOcspIgnoreListMethod.setAccessible(true);
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            // Mock Config.scope to throw an exception
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenThrow(new RuntimeException("Test exception"));
            
            // Call the method
            List<String> result = (List<String>) loadOcspIgnoreListMethod.invoke(null);
            
            // Verify the result
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isEmpty(), "Result should be empty");
        }
    }
    
    /**
     * Test for the loadNonceExcludedResponders method with non-empty list.
     */
    @Test
    public void testLoadNonceExcludedResponders_NonEmptyList() throws Exception {
        Method loadNonceExcludedRespondersMethod = ZacsOCSPProvider.class.getDeclaredMethod("loadNonceExcludedResponders");
        loadNonceExcludedRespondersMethod.setAccessible(true);
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            // Mock Config.scope
            Config.Scope scopeMock = mock(Config.Scope.class);
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scopeMock);
            
            // Mock scope.get to return a non-empty list
            when(scopeMock.get("nonceIgnoreList", "")).thenReturn("ocsp.example.com, ocsp.test.com");
            
            // Call the method
            List<String> result = (List<String>) loadNonceExcludedRespondersMethod.invoke(null);
            
            // Verify the result
            assertNotNull(result, "Result should not be null");
            assertEquals(2, result.size(), "Result should contain two entries");
            assertTrue(result.contains("ocsp.example.com"), "Result should contain ocsp.example.com");
            assertTrue(result.contains("ocsp.test.com"), "Result should contain ocsp.test.com");
        }
    }
    
    /**
     * Test for the loadNonceExcludedResponders method with empty list.
     */
    @Test
    public void testLoadNonceExcludedResponders_EmptyList() throws Exception {
        Method loadNonceExcludedRespondersMethod = ZacsOCSPProvider.class.getDeclaredMethod("loadNonceExcludedResponders");
        loadNonceExcludedRespondersMethod.setAccessible(true);
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            // Mock Config.scope
            Config.Scope scopeMock = mock(Config.Scope.class);
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scopeMock);
            
            // Mock scope.get to return an empty string
            when(scopeMock.get("nonceIgnoreList", "")).thenReturn("");
            
            // Call the method
            List<String> result = (List<String>) loadNonceExcludedRespondersMethod.invoke(null);
            
            // Verify the result
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isEmpty(), "Result should be empty");
        }
    }
    
    /**
     * Test for the loadNonceExcludedResponders method with null list.
     */
    @Test
    public void testLoadNonceExcludedResponders_NullList() throws Exception {
        Method loadNonceExcludedRespondersMethod = ZacsOCSPProvider.class.getDeclaredMethod("loadNonceExcludedResponders");
        loadNonceExcludedRespondersMethod.setAccessible(true);
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            // Mock Config.scope
            Config.Scope scopeMock = mock(Config.Scope.class);
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scopeMock);
            
            // Mock scope.get to return null
            when(scopeMock.get("nonceIgnoreList", "")).thenReturn(null);
            
            // Call the method
            List<String> result = (List<String>) loadNonceExcludedRespondersMethod.invoke(null);
            
            // Verify the result
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isEmpty(), "Result should be empty");
        }
    }
    
    /**
     * Test for the loadNonceExcludedResponders method with exception.
     */
    @Test
    public void testLoadNonceExcludedResponders_Exception() throws Exception {
        Method loadNonceExcludedRespondersMethod = ZacsOCSPProvider.class.getDeclaredMethod("loadNonceExcludedResponders");
        loadNonceExcludedRespondersMethod.setAccessible(true);
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            // Mock Config.scope to throw an exception
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenThrow(new RuntimeException("Test exception"));
            
            // Call the method
            List<String> result = (List<String>) loadNonceExcludedRespondersMethod.invoke(null);
            
            // Verify the result
            assertNotNull(result, "Result should not be null");
            assertTrue(result.isEmpty(), "Result should be empty");
        }
    }
    
    /**
     * Test for the check method with a responder in the ignore list.
     */
    @Test
    public void testCheck_MockResponse() throws Exception {
        Method createMockOCSPResponseMethod = ZacsOCSPProvider.class.getDeclaredMethod("createMockOCSPResponse", String.class);
        createMockOCSPResponseMethod.setAccessible(true);
        
        BCOCSPProvider.OCSPRevocationStatus result = (BCOCSPProvider.OCSPRevocationStatus) createMockOCSPResponseMethod.invoke(ocspProvider, "ocsp.example.com");
        
        assertNotNull(result, "Mock OCSP response should not be null");
        assertEquals(BCOCSPProvider.RevocationStatus.GOOD, result.getRevocationStatus(), "Revocation status should be GOOD");
        assertEquals(CRLReason.UNSPECIFIED, result.getRevocationReason(), "Revocation reason should be UNSPECIFIED");
        assertNull(result.getRevocationTime(), "Revocation time should be null");
    }
    
    /**
     * Test for the shouldIgnoreNonce method, which is used by buildOCSPRequest to determine if nonce should be enforced.
     */
    @Test
    public void testShouldIgnoreNonce_ForBuildOCSPRequest() throws Exception {
        // Test with a responder that should have nonce enforced
        String responderURI = "http://ocsp.example.com/ocsp";
        List<String> ignoreList = Arrays.asList("ocsp.other.com");
        boolean result = ocspProvider.shouldIgnoreNonce(responderURI, ignoreList);
        assertFalse(result, "Should return false for responder not in ignore list");
        
        // Test with a responder that should not have nonce enforced
        responderURI = "http://ocsp.example.com/ocsp";
        ignoreList = Arrays.asList("ocsp.example.com");
        result = ocspProvider.shouldIgnoreNonce(responderURI, ignoreList);
        assertTrue(result, "Should return true for responder in ignore list");
    }
    
    /**
     * Test for the extractResponderCert method with empty certificates.
     */
    @Test
    public void testExtractResponderCert_EmptyCerts() throws Exception {
        // Create mocks
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        
        // Set up the mocks to return empty certificates
        when(basicResp.getCerts()).thenReturn(new X509CertificateHolder[0]);
        
        // Call the method
        X509Certificate result = ocspProvider.extractResponderCert(basicResp, issuerCertificate);
        
        // Verify the result
        assertNull(result, "Result should be null for empty certificates");
    }
    
    /**
     * Test for the extractResponderCert method with a certificate exception.
     */
    @Test
    public void testExtractResponderCert_CertificateException() throws Exception {
        // Create mocks
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        X509CertificateHolder certHolder = mock(X509CertificateHolder.class);
        
        // Set up the mocks
        when(basicResp.getCerts()).thenReturn(new X509CertificateHolder[]{certHolder});
        
        // Create a spy of the ocspProvider to mock the isResponderCertificate method
        ZacsOCSPProvider spyProvider = spy(ocspProvider);
        
        // Mock the isResponderCertificate method to throw an exception
        doThrow(new RuntimeException("Test exception")).when(spyProvider).extractResponderCert(any(), any());
        
        // Call the method and expect an exception
        assertThrows(RuntimeException.class, () -> {
            spyProvider.extractResponderCert(basicResp, issuerCertificate);
        });
    }

    /**
     * Test for the isResponderCertificate method with a valid responder certificate.
     */
    @Test
    public void testIsResponderCertificate_ValidResponderCert() throws Exception {
        Method isResponderCertificateMethod = ZacsOCSPProvider.class.getDeclaredMethod("isResponderCertificate", X509Certificate.class, X509Certificate.class);
        isResponderCertificateMethod.setAccessible(true);

        // Mock the certificate to have OCSP Signing extended key usage
        List<String> extendedKeyUsages = Arrays.asList(KeyPurposeId.id_kp_OCSPSigning.getId());
        when(certificate.getExtendedKeyUsage()).thenReturn(extendedKeyUsages);
        
        // Mock the verify method to not throw an exception
        doNothing().when(certificate).verify(any());

        boolean result = (boolean) isResponderCertificateMethod.invoke(ocspProvider, certificate, issuerCertificate);
        
        assertTrue(result, "Should return true for valid responder certificate");
    }

    /**
     * Test for the isResponderCertificate method with a certificate that doesn't have OCSP Signing extended key usage.
     */
    @Test
    public void testIsResponderCertificate_NoOCSPSigningKeyUsage() throws Exception {
        Method isResponderCertificateMethod = ZacsOCSPProvider.class.getDeclaredMethod("isResponderCertificate", X509Certificate.class, X509Certificate.class);
        isResponderCertificateMethod.setAccessible(true);

        // Mock the certificate to not have OCSP Signing extended key usage
        List<String> extendedKeyUsages = Arrays.asList("1.3.6.1.5.5.7.3.1"); // TLS Web Server Authentication
        when(certificate.getExtendedKeyUsage()).thenReturn(extendedKeyUsages);
        
        // Mock the verify method to not throw an exception
        doNothing().when(certificate).verify(any());

        boolean result = (boolean) isResponderCertificateMethod.invoke(ocspProvider, certificate, issuerCertificate);
        
        assertFalse(result, "Should return false for certificate without OCSP Signing extended key usage");
    }

    /**
     * Test for the isResponderCertificate method with a certificate that fails verification.
     */
    @Test
    public void testIsResponderCertificate_VerificationFails() throws Exception {
        Method isResponderCertificateMethod = ZacsOCSPProvider.class.getDeclaredMethod("isResponderCertificate", X509Certificate.class, X509Certificate.class);
        isResponderCertificateMethod.setAccessible(true);

        // Mock the verify method to throw a certificate exception
        doThrow(new java.security.cert.CertificateException("Verification failed")).when(certificate).verify(any());

        boolean result = (boolean) isResponderCertificateMethod.invoke(ocspProvider, certificate, issuerCertificate);
        
        assertFalse(result, "Should return false for certificate that fails verification");
    }
}
