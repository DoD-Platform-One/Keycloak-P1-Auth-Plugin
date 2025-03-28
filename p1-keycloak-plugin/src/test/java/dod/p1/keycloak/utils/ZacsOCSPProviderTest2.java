package dod.p1.keycloak.utils;

import dod.p1.keycloak.utils.TestCertificateGenerator;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.crypto.def.BCOCSPProvider;
import org.mockito.MockedStatic;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Extra tests for ZacsOCSPProvider to improve code coverage by exercising its internal methods.
 * This version uses reflection to invoke the private methods in ZacsOCSPProvider.
 */
public class ZacsOCSPProviderTest2 {

    // Set up a static configuration mock so that ZacsOCSPProvider's static initializer works.
    private static final MockedStatic<Config> STATIC_CONFIG_MOCK;
    static {
        STATIC_CONFIG_MOCK = mockStatic(Config.class);
        Config.Scope scopeMock = mock(Config.Scope.class);
        STATIC_CONFIG_MOCK.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scopeMock);
        // Provide non-null values so that .trim() calls succeed.
        when(scopeMock.get("ignoreList", "")).thenReturn("");
        when(scopeMock.get("nonceIgnoreList", "")).thenReturn("");
    }

    @AfterAll
    public static void tearDownAll() {
        STATIC_CONFIG_MOCK.close();
    }

    /**
     * Helper method to invoke a private method using reflection.
     *
     * @param instance       the object instance to call the method on
     * @param methodName     the private method name
     * @param parameterTypes the parameter types
     * @param args           the method arguments
     * @param <T>            the expected return type
     * @return the result from the invoked method
     * @throws Exception if reflection fails
     */
    private <T> T invokePrivateMethod(Object instance, String methodName, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        Method method = instance.getClass().getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        return (T) method.invoke(instance, args);
    }

    @Test
    public void testGenerateNonce() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        byte[] nonce1 = invokePrivateMethod(provider, "generateNonce", new Class[]{});
        byte[] nonce2 = invokePrivateMethod(provider, "generateNonce", new Class[]{});
        assertNotNull(nonce1);
        assertEquals(16, nonce1.length);
        assertFalse(java.util.Arrays.equals(nonce1, nonce2));
    }

    @Test
    public void testCompareCertIDs() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        X509Certificate cert = TestCertificateGenerator.generateSelfSignedCertificate();
        org.bouncycastle.operator.DigestCalculatorProvider digestProvider =
                new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build();
        Object id1 = new org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID(
                digestProvider.get(CertificateID.HASH_SHA1), cert, cert.getSerialNumber());
        Object id2 = new org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID(
                digestProvider.get(CertificateID.HASH_SHA1), cert, cert.getSerialNumber());
        boolean equal = invokePrivateMethod(provider, "compareCertIDs",
                new Class[]{id1.getClass(), CertificateID.class}, id1, id2);
        assertTrue(equal);
        Object id3 = new org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID(
                digestProvider.get(CertificateID.HASH_SHA1), cert, cert.getSerialNumber().add(BigInteger.ONE));
        boolean notEqual = invokePrivateMethod(provider, "compareCertIDs",
                new Class[]{id1.getClass(), CertificateID.class}, id1, id3);
        assertFalse(notEqual);
    }

    @Test
    public void testSingleResponseToRevocationStatusGood() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        when(singleResp.getCertStatus()).thenReturn(CertificateStatus.GOOD);
        BCOCSPProvider.OCSPRevocationStatus status = invokePrivateMethod(provider, "singleResponseToRevocationStatus",
                new Class[]{SingleResp.class}, singleResp);
        assertEquals(BCOCSPProvider.RevocationStatus.GOOD, status.getRevocationStatus());
        assertNull(status.getRevocationTime());
        assertEquals(java.security.cert.CRLReason.UNSPECIFIED, status.getRevocationReason());
    }

    @Test
    public void testSingleResponseToRevocationStatusRevoked() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        RevokedStatus revokedStatus = mock(RevokedStatus.class);
        Date revocationTime = new Date();
        when(revokedStatus.getRevocationTime()).thenReturn(revocationTime);
        when(revokedStatus.hasRevocationReason()).thenReturn(true);
        when(revokedStatus.getRevocationReason()).thenReturn(0);
        when(singleResp.getCertStatus()).thenReturn(revokedStatus);
        BCOCSPProvider.OCSPRevocationStatus status = invokePrivateMethod(provider, "singleResponseToRevocationStatus",
                new Class[]{SingleResp.class}, singleResp);
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
                new Class[]{SingleResp.class}, singleResp);
        assertEquals(BCOCSPProvider.RevocationStatus.UNKNOWN, status.getRevocationStatus());
    }

    @Test
    public void testCheckResponseValidityValid() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        Date now = new Date();
        // thisUpdate 1 minute ago, nextUpdate 1 minute in future.
        when(singleResp.getThisUpdate()).thenReturn(new Date(now.getTime() - 60000));
        when(singleResp.getNextUpdate()).thenReturn(new Date(now.getTime() + 60000));
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        when(basicResp.getResponses()).thenReturn(new SingleResp[]{singleResp});
        assertDoesNotThrow(() -> invokePrivateMethod(provider, "checkResponseValidity",
                new Class[]{BasicOCSPResp.class, Date.class}, basicResp, now));
    }

    @Test
    public void testCheckResponseValidityNotYetValid() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        Date now = new Date();
        // thisUpdate 10 minutes in future.
        when(singleResp.getThisUpdate()).thenReturn(new Date(now.getTime() + 10 * 60 * 1000));
        when(singleResp.getNextUpdate()).thenReturn(new Date(now.getTime() + 20 * 60 * 1000));
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        when(basicResp.getResponses()).thenReturn(new SingleResp[]{singleResp});
        try {
            invokePrivateMethod(provider, "checkResponseValidity", new Class[]{BasicOCSPResp.class, Date.class}, basicResp, now);
            fail("Expected CertPathValidatorException for not yet valid response");
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            assertTrue(cause instanceof CertPathValidatorException);
            assertTrue(cause.getMessage().contains("not yet valid"));
        }
    }

    @Test
    public void testCheckResponseValidityExpired() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        SingleResp singleResp = mock(SingleResp.class);
        Date now = new Date();
        // Set thisUpdate 20 minutes ago and nextUpdate 10 minutes ago.
        when(singleResp.getThisUpdate()).thenReturn(new Date(now.getTime() - 20 * 60 * 1000));
        when(singleResp.getNextUpdate()).thenReturn(new Date(now.getTime() - 10 * 60 * 1000));
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        when(basicResp.getResponses()).thenReturn(new SingleResp[]{singleResp});
        try {
            invokePrivateMethod(provider, "checkResponseValidity", new Class[]{BasicOCSPResp.class, Date.class}, basicResp, now);
            fail("Expected CertPathValidatorException for expired response");
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            assertTrue(cause instanceof CertPathValidatorException);
            assertTrue(cause.getMessage().contains("expired"));
        }
    }

    @Test
    public void testVerifySignatureValid() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        X509Certificate cert = TestCertificateGenerator.generateSelfSignedCertificate();
        when(basicResp.isSignatureValid(any())).thenReturn(true);
        boolean result = invokePrivateMethod(provider, "verifySignature", new Class[]{BasicOCSPResp.class, X509Certificate.class}, basicResp, cert);
        assertTrue(result);
    }

    @Test
    public void testVerifySignatureInvalid() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        X509Certificate cert = TestCertificateGenerator.generateSelfSignedCertificate();
        when(basicResp.isSignatureValid(any())).thenThrow(new RuntimeException("test exception"));
        try {
            invokePrivateMethod(provider, "verifySignature", new Class[]{BasicOCSPResp.class, X509Certificate.class}, basicResp, cert);
            fail("Expected RuntimeException wrapped in InvocationTargetException");
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            assertNotNull(cause);
            assertEquals("test exception", cause.getMessage());
        }
    }

    @Test
    public void testIsResponderCertificateValid() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        // Our generated test certificate does not have OCSP Signing extended key usage.
        // Therefore, we expect the check to return false.
        X509Certificate cert = TestCertificateGenerator.generateSelfSignedCertificate();
        boolean result = invokePrivateMethod(provider, "isResponderCertificate", new Class[]{X509Certificate.class, X509Certificate.class}, cert, cert);
        assertFalse(result);
    }

    @Test
    public void testIsResponderCertificateInvalid() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        X509Certificate cert1 = TestCertificateGenerator.generateSelfSignedCertificate();
        X509Certificate cert2 = TestCertificateGenerator.generateSelfSignedCertificate();
        boolean result = invokePrivateMethod(provider, "isResponderCertificate", new Class[]{X509Certificate.class, X509Certificate.class}, cert1, cert2);
        assertFalse(result);
    }

    @Test
    public void testExtractResponderCertNotFound() throws Exception {
        ZacsOCSPProvider provider = new ZacsOCSPProvider();
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        // Return an empty array for getCerts()
        when(basicResp.getCerts()).thenReturn(new org.bouncycastle.cert.X509CertificateHolder[]{});
        X509Certificate issuer = TestCertificateGenerator.generateSelfSignedCertificate();
        X509Certificate result = invokePrivateMethod(provider, "extractResponderCert", new Class[]{BasicOCSPResp.class, X509Certificate.class}, basicResp, issuer);
        assertNull(result);
    }
}
