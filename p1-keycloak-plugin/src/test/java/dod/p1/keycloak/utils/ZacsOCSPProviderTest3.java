package dod.p1.keycloak.utils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.HexFormat;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.crypto.def.BCOCSPProvider;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Additional tests for ZacsOCSPProvider to improve coverage.
 */
public class ZacsOCSPProviderTest3 {

    // Stub static config so that Config.scope returns a non-null scope.
    private static MockedStatic<Config> STATIC_CONFIG_MOCK;
    static {
        Config.Scope scopeMock = mock(Config.Scope.class);
        when(scopeMock.get(any(String.class), any(String.class))).thenReturn("");
        STATIC_CONFIG_MOCK = Mockito.mockStatic(Config.class);
        STATIC_CONFIG_MOCK.when(() -> Config.scope(any(String.class))).thenReturn(scopeMock);
    }

    @AfterAll
    public static void tearDownAll() {
        STATIC_CONFIG_MOCK.close();
    }

    /**
     * Helper method to invoke a private method using reflection.
     */
    private <T> T invokePrivateMethod(Object instance, String methodName, Class<?>[] paramTypes, Object... args)
            throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return (T) method.invoke(instance, args);
    }

    @Test
    public void testVerifySignatureInvalid() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        X509Certificate cert = TestCertificateGenerator.generateSelfSignedCertificate();
        when(basicResp.isSignatureValid(any())).thenThrow(new RuntimeException("test exception"));
        Exception ex = assertThrows(InvocationTargetException.class, () -> {
            invokePrivateMethod(provider, "verifySignature",
                    new Class[] { BasicOCSPResp.class, X509Certificate.class }, basicResp, cert);
        });
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertEquals("test exception", cause.getMessage());
    }

    @Test
    public void testSingleResponseToRevocationStatusGood() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        // GOOD is represented by a null certificate status.
        SingleResp singleResp = mock(SingleResp.class);
        when(singleResp.getCertStatus()).thenReturn(CertificateStatus.GOOD);
        BCOCSPProvider.OCSPRevocationStatus status = invokePrivateMethod(provider, "singleResponseToRevocationStatus",
                new Class[] { SingleResp.class }, singleResp);
        assertEquals(BCOCSPProvider.RevocationStatus.GOOD, status.getRevocationStatus());
        assertNull(status.getRevocationTime());
        assertEquals(java.security.cert.CRLReason.UNSPECIFIED, status.getRevocationReason());
    }

    @Test
    public void testSingleResponseToRevocationStatusRevoked() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        RevokedStatus revokedStatus = mock(RevokedStatus.class);
        Date revocationTime = new Date();
        when(revokedStatus.getRevocationTime()).thenReturn(revocationTime);
        when(revokedStatus.hasRevocationReason()).thenReturn(true);
        when(revokedStatus.getRevocationReason()).thenReturn(0); // 0 = UNSPECIFIED

        SingleResp singleResp = mock(SingleResp.class);
        when(singleResp.getCertStatus()).thenReturn(revokedStatus);
        
        BCOCSPProvider.OCSPRevocationStatus status = invokePrivateMethod(provider, "singleResponseToRevocationStatus",
                new Class[] { SingleResp.class }, singleResp);
        assertEquals(BCOCSPProvider.RevocationStatus.REVOKED, status.getRevocationStatus());
        assertEquals(revocationTime, status.getRevocationTime());
        assertEquals(java.security.cert.CRLReason.UNSPECIFIED, status.getRevocationReason());
    }

    @Test
    public void testSingleResponseToRevocationStatusUnknown() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        when(singleResp.getCertStatus()).thenReturn(new UnknownStatus());
        
        BCOCSPProvider.OCSPRevocationStatus status = invokePrivateMethod(provider, "singleResponseToRevocationStatus",
                new Class[] { SingleResp.class }, singleResp);
        assertEquals(BCOCSPProvider.RevocationStatus.UNKNOWN, status.getRevocationStatus());
    }

    @Test
    public void testCheckResponseValidityValid() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        when(singleResp.getThisUpdate()).thenReturn(new Date(System.currentTimeMillis() - 60000));
        when(singleResp.getNextUpdate()).thenReturn(new Date(System.currentTimeMillis() + 60000));
        
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        when(basicResp.getResponses()).thenReturn(new SingleResp[] { singleResp });
        
        assertDoesNotThrow(() -> invokePrivateMethod(provider, "checkResponseValidity",
                new Class[] { BasicOCSPResp.class, Date.class }, basicResp, new Date()));
    }

    @Test
    public void testCheckResponseValidityNotYetValid() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        when(singleResp.getThisUpdate()).thenReturn(new Date(System.currentTimeMillis() + 10 * 60 * 1000));
        when(singleResp.getNextUpdate()).thenReturn(new Date(System.currentTimeMillis() + 20 * 60 * 1000));
        
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        when(basicResp.getResponses()).thenReturn(new SingleResp[] { singleResp });
        
        Exception ex = assertThrows(InvocationTargetException.class, () -> invokePrivateMethod(provider,
                "checkResponseValidity", new Class[] { BasicOCSPResp.class, Date.class }, basicResp, new Date()));
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause.getMessage().contains("not yet valid"));
    }

    @Test
    public void testCheckResponseValidityExpired() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        when(singleResp.getThisUpdate()).thenReturn(new Date(System.currentTimeMillis() - 20 * 60 * 1000));
        when(singleResp.getNextUpdate()).thenReturn(new Date(System.currentTimeMillis() - 10 * 60 * 1000));
        
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        when(basicResp.getResponses()).thenReturn(new SingleResp[] { singleResp });
        
        Exception ex = assertThrows(InvocationTargetException.class, () -> invokePrivateMethod(provider,
                "checkResponseValidity", new Class[] { BasicOCSPResp.class, Date.class }, basicResp, new Date()));
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause.getMessage().contains("expired"));
    }

    @Test
    public void testValidateResponderCertificate_NullResponder() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        X509Certificate issuerCert = TestCertificateGenerator.generateSelfSignedCertificate();
        Exception ex = assertThrows(InvocationTargetException.class,
                () -> invokePrivateMethod(provider, "validateResponderCertificate",
                        new Class[] { X509Certificate.class, X509Certificate.class, Date.class },
                        (X509Certificate) null, issuerCert, new Date()));
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause.getMessage().contains("Responder certificate is null"));
    }

    @Test
    public void testProcessBasicOCSPResponse_NoMatchingResponse() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        when(basicResp.getResponses()).thenReturn(new SingleResp[] {});
        X509Certificate testCert = TestCertificateGenerator.generateSelfSignedCertificate();
        JcaCertificateID certID = new JcaCertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                testCert, testCert.getSerialNumber());
        Exception ex = assertThrows(InvocationTargetException.class,
                () -> invokePrivateMethod(provider, "processBasicOCSPResponse",
                        new Class[] { X509Certificate.class, X509Certificate.class, Date.class, JcaCertificateID.class,
                                DEROctetString.class, BasicOCSPResp.class, boolean.class },
                        testCert, testCert, new Date(), certID, null, basicResp, true));
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause.getMessage().contains("does not include a response"));
    }

    @Test
    public void testProcessBasicOCSPResponse_Success() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        X509Certificate testCert = TestCertificateGenerator.generateSelfSignedCertificate();
        JcaCertificateID certID = new JcaCertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                testCert, testCert.getSerialNumber());
                
        // Create a mock SingleResp with GOOD status
        SingleResp singleResp = mock(SingleResp.class);
        when(singleResp.getCertID()).thenReturn(certID);
        when(singleResp.getCertStatus()).thenReturn(CertificateStatus.GOOD);
        
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        when(basicResp.getResponses()).thenReturn(new SingleResp[] { singleResp });
        when(basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)).thenReturn(null);
        when(basicResp.isSignatureValid(any())).thenReturn(true);
        
        // Create a mock responder certificate with proper OCSP Signing extended key usage
        X509Certificate responderCert = mock(X509Certificate.class);
        doNothing().when(responderCert).verify(any());
        List<String> eku = List.of(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning.getId());
        when(responderCert.getExtendedKeyUsage()).thenReturn(eku);
        doNothing().when(responderCert).checkValidity(any(Date.class));

        Object result = invokePrivateMethod(provider, "processBasicOCSPResponse",
                new Class[] { X509Certificate.class, X509Certificate.class, Date.class, JcaCertificateID.class,
                        DEROctetString.class, BasicOCSPResp.class, boolean.class },
                testCert, responderCert, new Date(), certID, null, basicResp, false);
        assertNotNull(result);
        BCOCSPProvider.OCSPRevocationStatus status = (BCOCSPProvider.OCSPRevocationStatus) result;
        assertEquals(BCOCSPProvider.RevocationStatus.GOOD, status.getRevocationStatus());
    }

    @Test
    public void testVerifyResponseWithNonceEnforced() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        X509Certificate issuerCert = TestCertificateGenerator.generateSelfSignedCertificate();
        X509Certificate responderCert = mock(X509Certificate.class);
        
        // Mock the responder certificate validation
        doNothing().when(responderCert).verify(any());
        List<String> eku = List.of(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning.getId());
        when(responderCert.getExtendedKeyUsage()).thenReturn(eku);
        
        // Mock the response signature validation
        when(basicResp.isSignatureValid(any())).thenReturn(true);
        
        // Mock the response validity period
        SingleResp singleResp = mock(SingleResp.class);
        when(singleResp.getThisUpdate()).thenReturn(new Date(System.currentTimeMillis() - 60000));
        when(singleResp.getNextUpdate()).thenReturn(new Date(System.currentTimeMillis() + 60000));
        when(basicResp.getResponses()).thenReturn(new SingleResp[] { singleResp });
        
        // Create a nonce for testing
        byte[] nonceBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        DEROctetString requestNonce = new DEROctetString(nonceBytes);
        
        // Mock the nonce extension in the response
        when(basicResp.hasExtensions()).thenReturn(true);
        org.bouncycastle.asn1.x509.Extension responseNonce = mock(org.bouncycastle.asn1.x509.Extension.class);
        when(basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)).thenReturn(responseNonce);
        
        // Mock the nonce value in the response
        org.bouncycastle.asn1.ASN1OctetString octetString = mock(org.bouncycastle.asn1.ASN1OctetString.class);
        when(responseNonce.getExtnValue()).thenReturn(octetString);
        when(octetString.getOctets()).thenReturn(nonceBytes);
        
        // Test with enforced nonce
        assertDoesNotThrow(() -> invokePrivateMethod(provider, "verifyResponse",
                new Class[] { BasicOCSPResp.class, X509Certificate.class, X509Certificate.class,
                        DEROctetString.class, Date.class, boolean.class },
                basicResp, issuerCert, responderCert, requestNonce, new Date(), true));
    }

    @Test
    public void testVerifyResponseWithNonceMismatch() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        X509Certificate issuerCert = TestCertificateGenerator.generateSelfSignedCertificate();
        X509Certificate responderCert = mock(X509Certificate.class);
        
        // Create request and response nonces with different values
        byte[] requestNonceBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] responseNonceBytes = new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        DEROctetString requestNonce = new DEROctetString(requestNonceBytes);
        
        // Mock the nonce extension in the response
        when(basicResp.hasExtensions()).thenReturn(true);
        org.bouncycastle.asn1.x509.Extension responseNonce = mock(org.bouncycastle.asn1.x509.Extension.class);
        when(basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)).thenReturn(responseNonce);
        
        // Mock the nonce value in the response with a different value
        org.bouncycastle.asn1.ASN1OctetString octetString = mock(org.bouncycastle.asn1.ASN1OctetString.class);
        when(responseNonce.getExtnValue()).thenReturn(octetString);
        when(octetString.getOctets()).thenReturn(responseNonceBytes);
        
        // Test with enforced nonce but mismatched values
        Exception ex = assertThrows(InvocationTargetException.class, () -> invokePrivateMethod(provider, "verifyResponse",
                new Class[] { BasicOCSPResp.class, X509Certificate.class, X509Certificate.class,
                        DEROctetString.class, Date.class, boolean.class },
                basicResp, issuerCert, responderCert, requestNonce, new Date(), true));
        
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause instanceof CertPathValidatorException);
        assertTrue(cause.getMessage().contains("Nonces do not match"));
    }

    @Test
    public void testVerifyResponseWithMissingNonce() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        X509Certificate issuerCert = TestCertificateGenerator.generateSelfSignedCertificate();
        X509Certificate responderCert = mock(X509Certificate.class);
        
        // Create a request nonce
        byte[] requestNonceBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        DEROctetString requestNonce = new DEROctetString(requestNonceBytes);
        
        // Mock the response to have no nonce extension
        when(basicResp.hasExtensions()).thenReturn(false);
        when(basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)).thenReturn(null);
        
        // Test with enforced nonce but missing in response
        Exception ex = assertThrows(InvocationTargetException.class, () -> invokePrivateMethod(provider, "verifyResponse",
                new Class[] { BasicOCSPResp.class, X509Certificate.class, X509Certificate.class,
                        DEROctetString.class, Date.class, boolean.class },
                basicResp, issuerCert, responderCert, requestNonce, new Date(), true));
        
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause instanceof CertPathValidatorException);
        assertTrue(cause.getMessage().contains("Nonce missing in OCSP response"));
    }

    @Test
    public void testValidateResponderCertificateWithInvalidSignature() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        X509Certificate responderCert = mock(X509Certificate.class);
        X509Certificate issuerCert = TestCertificateGenerator.generateSelfSignedCertificate();
        
        // Mock the responder certificate to fail verification
        doThrow(new java.security.SignatureException("Invalid signature")).when(responderCert).verify(any());
        
        Exception ex = assertThrows(InvocationTargetException.class, () -> invokePrivateMethod(provider, "validateResponderCertificate",
                new Class[] { X509Certificate.class, X509Certificate.class, Date.class },
                responderCert, issuerCert, new Date()));
        
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause instanceof CertPathValidatorException);
        assertTrue(cause.getMessage().contains("Responder certificate verification failed"));
    }

    @Test
    public void testValidateResponderCertificateWithoutOCSPSigningEKU() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        X509Certificate responderCert = mock(X509Certificate.class);
        X509Certificate issuerCert = TestCertificateGenerator.generateSelfSignedCertificate();
        
        // Mock the responder certificate to pass verification
        doNothing().when(responderCert).verify(any());
        
        // Mock the extended key usage to not include OCSP Signing
        List<String> eku = List.of("1.3.6.1.5.5.7.3.1"); // TLS Web Server Authentication, not OCSP Signing
        when(responderCert.getExtendedKeyUsage()).thenReturn(eku);
        
        Exception ex = assertThrows(InvocationTargetException.class, () -> invokePrivateMethod(provider, "validateResponderCertificate",
                new Class[] { X509Certificate.class, X509Certificate.class, Date.class },
                responderCert, issuerCert, new Date()));
        
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause instanceof CertPathValidatorException);
        assertTrue(cause.getMessage().contains("does not have OCSP Signing extended key usage"));
    }

    @Test
    public void testValidateResponderCertificateWithExpiredCertificate() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        X509Certificate responderCert = mock(X509Certificate.class);
        X509Certificate issuerCert = TestCertificateGenerator.generateSelfSignedCertificate();
        
        // Mock the responder certificate to pass verification
        doNothing().when(responderCert).verify(any());
        
        // Mock the extended key usage to include OCSP Signing
        List<String> eku = List.of(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning.getId());
        when(responderCert.getExtendedKeyUsage()).thenReturn(eku);
        
        // Mock the certificate to be expired
        doThrow(new java.security.cert.CertificateExpiredException("Certificate expired")).when(responderCert).checkValidity(any(Date.class));
        
        Exception ex = assertThrows(InvocationTargetException.class, () -> invokePrivateMethod(provider, "validateResponderCertificate",
                new Class[] { X509Certificate.class, X509Certificate.class, Date.class },
                responderCert, issuerCert, new Date()));
        
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause instanceof CertPathValidatorException);
        assertTrue(cause.getMessage().contains("Responder certificate is not valid"));
    }

    @Test
    public void testSingleResponseToRevocationStatusWithUnrecognizedStatus() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        
        // Create a custom certificate status that is neither GOOD, REVOKED, nor UNKNOWN
        CertificateStatus customStatus = new CertificateStatus() {
            // Custom implementation that doesn't match any of the standard types
        };
        when(singleResp.getCertStatus()).thenReturn(customStatus);
        
        Exception ex = assertThrows(InvocationTargetException.class, () -> invokePrivateMethod(provider, "singleResponseToRevocationStatus",
                new Class[] { SingleResp.class }, singleResp));
        
        Throwable cause = ex.getCause();
        assertNotNull(cause);
        assertTrue(cause instanceof CertPathValidatorException);
        assertTrue(cause.getMessage().contains("Unrecognized revocation status"));
    }

    @Test
    public void testRevokedStatusWithoutRevocationReason() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        RevokedStatus revokedStatus = mock(RevokedStatus.class);
        Date revocationTime = new Date();
        
        when(revokedStatus.getRevocationTime()).thenReturn(revocationTime);
        when(revokedStatus.hasRevocationReason()).thenReturn(false); // No revocation reason
        when(singleResp.getCertStatus()).thenReturn(revokedStatus);
        
        BCOCSPProvider.OCSPRevocationStatus status = invokePrivateMethod(provider, "singleResponseToRevocationStatus",
                new Class[] { SingleResp.class }, singleResp);
        
        assertEquals(BCOCSPProvider.RevocationStatus.REVOKED, status.getRevocationStatus());
        assertEquals(revocationTime, status.getRevocationTime());
        assertEquals(java.security.cert.CRLReason.UNSPECIFIED, status.getRevocationReason()); // Default reason
    }
}
