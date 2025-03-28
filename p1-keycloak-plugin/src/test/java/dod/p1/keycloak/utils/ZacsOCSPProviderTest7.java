package dod.p1.keycloak.utils;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
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
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
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
 * Additional test class for {@link ZacsOCSPProvider} to improve test coverage.
 * This class focuses on methods with lower coverage in the JaCoCo report.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class ZacsOCSPProviderTest7 {

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
     * Test for the extractResponderCert method with empty certificates.
     * This test covers the branch where the certificates array is empty.
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
     * Test for the isResponderCertificate method when certificate verification fails.
     * This test covers the branch where the certificate verification throws an exception.
     */
    @Test
    public void testIsResponderCertificate_VerificationFails() throws Exception {
        // Get the isResponderCertificate method
        Method isResponderCertificateMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "isResponderCertificate", X509Certificate.class, X509Certificate.class);
        isResponderCertificateMethod.setAccessible(true);
        
        // Mock the certificate to throw an exception when verify is called
        doThrow(new java.security.cert.CertificateException("Verification failed"))
            .when(certificate).verify(any());
        
        // Call the method
        boolean result = (boolean) isResponderCertificateMethod.invoke(ocspProvider, certificate, issuerCertificate);
        
        // Verify the result
        assertFalse(result, "Should return false when certificate verification fails");
    }

    /**
     * Test for the validateResponderURIs method with a null list.
     * This test covers the branch where the responder URIs list is null.
     */
    @Test
    public void testValidateResponderURIs_NullList() throws Exception {
        // Get the validateResponderURIs method
        Method validateResponderURIsMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "validateResponderURIs", List.class);
        validateResponderURIsMethod.setAccessible(true);

        // Call the method with null and expect an IllegalArgumentException
        Exception exception = assertThrows(Exception.class, () -> {
            validateResponderURIsMethod.invoke(ocspProvider, (Object) null);
        });

        // Verify that the cause is an IllegalArgumentException
        Throwable cause = exception.getCause();
        assertTrue(cause instanceof IllegalArgumentException,
                "Cause should be IllegalArgumentException but was " + cause.getClass().getName());
        assertEquals("Need at least one responder URI", cause.getMessage());
    }

    /**
     * Test for the check method with a mock OCSP response.
     * This test verifies that the createMockOCSPResponse method returns the expected result.
     */
    @Test
    public void testCheck_MockResponse() throws Exception {
        // Get the createMockOCSPResponse method
        Method createMockOCSPResponseMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "createMockOCSPResponse", String.class);
        createMockOCSPResponseMethod.setAccessible(true);
        
        // Call the method
        BCOCSPProvider.OCSPRevocationStatus result =
                (BCOCSPProvider.OCSPRevocationStatus) createMockOCSPResponseMethod.invoke(
                        ocspProvider, "ocsp.example.com");
        
        // Verify the result
        assertNotNull(result, "Mock OCSP response should not be null");
        assertEquals(BCOCSPProvider.RevocationStatus.GOOD, result.getRevocationStatus(),
                "Revocation status should be GOOD");
    }

    /**
     * Test for the check method with an exception during certificate ID creation.
     * This test covers the branch where an exception is thrown during certificate ID creation.
     */
    @Test
    public void testCheck_CertificateIDCreationException() throws Exception {
        // Create a list of responder URIs
        URI responderURI = new URI("http://ocsp.example.com");
        List<URI> responderURIs = Arrays.asList(responderURI);

        // Mock the certificate to throw an exception when getSerialNumber is called
        when(certificate.getSerialNumber()).thenThrow(new RuntimeException("Test exception"));

        // Call the check method and expect a CertPathValidatorException
        Exception exception = assertThrows(CertPathValidatorException.class, () -> {
            ocspProvider.check(keycloakSession, certificate, issuerCertificate, responderURIs, null, new Date());
        });

        // Verify the exception message
        assertTrue(exception.getMessage().contains("OCSP check failed"),
                "Exception message should contain 'OCSP check failed'");
    }

    /**
     * Test for the compareCertIDs method when one of the IDs is null.
     * This test covers the branch where one of the certificate IDs is null.
     */
    @Test
    public void testCompareCertIDs_NullCertID() throws Exception {
        // Get the compareCertIDs method
        Method compareCertIDsMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "compareCertIDs", JcaCertificateID.class, CertificateID.class);
        compareCertIDsMethod.setAccessible(true);

        // Create a mock for one ID
        JcaCertificateID certID1 = mock(JcaCertificateID.class);

        // Call the method with null for the second ID
        boolean result = (boolean) compareCertIDsMethod.invoke(ocspProvider, certID1, null);

        // Verify the result
        assertFalse(result, "Should return false when one ID is null");

        // Call the method with null for the first ID
        result = (boolean) compareCertIDsMethod.invoke(ocspProvider, null, mock(CertificateID.class));

        // Verify the result
        assertFalse(result, "Should return false when one ID is null");
    }

    /**
     * Test for the verifyResponse method with a missing nonce in the response.
     * This test covers the branch where responseNonce is null.
     */
    @Test
    public void testVerifyResponse_MissingNonce() throws Exception {
        // Get the verifyResponse method
        Method verifyResponseMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "verifyResponse", BasicOCSPResp.class, X509Certificate.class, X509Certificate.class,
                DEROctetString.class, Date.class, boolean.class);
        verifyResponseMethod.setAccessible(true);

        // Create mocks
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        DEROctetString requestNonce = new DEROctetString(new byte[]{1, 2, 3, 4});
        Date date = new Date();

        // Set up the mocks
        when(basicResp.hasExtensions()).thenReturn(true);
        when(basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)).thenReturn(null);

        // Call the method and expect a CertPathValidatorException
        Exception exception = assertThrows(Exception.class, () -> {
            verifyResponseMethod.invoke(ocspProvider, basicResp, issuerCertificate, certificate,
                    requestNonce, date, true);
        });

        // Verify that the cause is a CertPathValidatorException
        Throwable cause = exception.getCause();
        assertTrue(cause instanceof CertPathValidatorException,
                "Cause should be CertPathValidatorException but was " + cause.getClass().getName());
        assertTrue(cause.getMessage().contains("Nonce missing"),
                "Exception message should mention missing nonce");
    }

    /**
     * Test for the verifyResponse method with non-matching nonces.
     * This test covers the branch where nonces don't match.
     */
    @Test
    public void testVerifyResponse_NonMatchingNonces() throws Exception {
        // Get the verifyResponse method
        Method verifyResponseMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "verifyResponse", BasicOCSPResp.class, X509Certificate.class, X509Certificate.class,
                DEROctetString.class, Date.class, boolean.class);
        verifyResponseMethod.setAccessible(true);

        // Create mocks
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        DEROctetString requestNonce = new DEROctetString(new byte[]{1, 2, 3, 4});
        Extension responseNonce = mock(Extension.class);
        org.bouncycastle.asn1.ASN1OctetString responseNonceValue = mock(org.bouncycastle.asn1.ASN1OctetString.class);
        Date date = new Date();

        // Set up the mocks
        when(basicResp.hasExtensions()).thenReturn(true);
        when(basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce)).thenReturn(responseNonce);
        when(responseNonce.getExtnValue()).thenReturn(responseNonceValue);
        when(responseNonceValue.getOctets()).thenReturn(new byte[]{5, 6, 7, 8}); // Different from requestNonce

        // Call the method and expect a CertPathValidatorException
        Exception exception = assertThrows(Exception.class, () -> {
            verifyResponseMethod.invoke(ocspProvider, basicResp, issuerCertificate, certificate,
                    requestNonce, date, true);
        });

        // Verify that the cause is a CertPathValidatorException
        Throwable cause = exception.getCause();
        assertTrue(cause instanceof CertPathValidatorException,
                "Cause should be CertPathValidatorException but was " + cause.getClass().getName());
        assertTrue(cause.getMessage().contains("Nonces do not match"),
                "Exception message should mention non-matching nonces");
    }

    /**
     * Test for the checkResponseValidity method with a response that is not yet valid.
     * This test covers the branch where currentDate is before thisUpdateMinusSkew.
     */
    @Test
    public void testCheckResponseValidity_NotYetValid() throws Exception {
        // Get the checkResponseValidity method
        Method checkResponseValidityMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "checkResponseValidity", BasicOCSPResp.class, Date.class);
        checkResponseValidityMethod.setAccessible(true);

        // Create mocks
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        SingleResp singleResp = mock(SingleResp.class);
        Date currentDate = new Date(System.currentTimeMillis() - 3600000); // 1 hour ago
        Date thisUpdate = new Date(System.currentTimeMillis()); // Now

        // Set up the mocks
        when(basicResp.getResponses()).thenReturn(new SingleResp[]{singleResp});
        when(singleResp.getThisUpdate()).thenReturn(thisUpdate);

        // Call the method and expect a CertPathValidatorException
        Exception exception = assertThrows(Exception.class, () -> {
            checkResponseValidityMethod.invoke(ocspProvider, basicResp, currentDate);
        });

        // Verify that the cause is a CertPathValidatorException
        Throwable cause = exception.getCause();
        assertTrue(cause instanceof CertPathValidatorException,
                "Cause should be CertPathValidatorException but was " + cause.getClass().getName());
        assertTrue(cause.getMessage().contains("not yet valid"),
                "Exception message should mention response not yet valid");
    }

    /**
     * Test for the checkResponseValidity method with an expired response.
     * This test covers the branch where currentDate is after nextUpdatePlusSkew.
     */
    @Test
    public void testCheckResponseValidity_Expired() throws Exception {
        // Get the checkResponseValidity method
        Method checkResponseValidityMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "checkResponseValidity", BasicOCSPResp.class, Date.class);
        checkResponseValidityMethod.setAccessible(true);

        // Create mocks
        BasicOCSPResp basicResp = mock(BasicOCSPResp.class);
        SingleResp singleResp = mock(SingleResp.class);
        Date currentDate = new Date(System.currentTimeMillis()); // Now
        Date thisUpdate = new Date(System.currentTimeMillis() - 7200000); // 2 hours ago
        Date nextUpdate = new Date(System.currentTimeMillis() - 3600000); // 1 hour ago

        // Set up the mocks
        when(basicResp.getResponses()).thenReturn(new SingleResp[]{singleResp});
        when(singleResp.getThisUpdate()).thenReturn(thisUpdate);
        when(singleResp.getNextUpdate()).thenReturn(nextUpdate);

        // Call the method and expect a CertPathValidatorException
        Exception exception = assertThrows(Exception.class, () -> {
            checkResponseValidityMethod.invoke(ocspProvider, basicResp, currentDate);
        });

        // Verify that the cause is a CertPathValidatorException
        Throwable cause = exception.getCause();
        assertTrue(cause instanceof CertPathValidatorException,
                "Cause should be CertPathValidatorException but was " + cause.getClass().getName());
        assertTrue(cause.getMessage().contains("expired"),
                "Exception message should mention response expired");
    }
    
    /**
     * Test for the compareCertIDs method with different certificate IDs.
     * This test covers the branch where the certificate IDs don't match.
     */
    @Test
    public void testCompareCertIDs_DifferentCertIDs() throws Exception {
        // Get the compareCertIDs method
        Method compareCertIDsMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "compareCertIDs", JcaCertificateID.class, CertificateID.class);
        compareCertIDsMethod.setAccessible(true);

        // Create mocks
        JcaCertificateID certID1 = mock(JcaCertificateID.class);
        CertificateID certID2 = mock(CertificateID.class);

        // Set up the mocks with different values
        when(certID1.getIssuerKeyHash()).thenReturn(new byte[]{1, 2, 3});
        when(certID2.getIssuerKeyHash()).thenReturn(new byte[]{4, 5, 6});
        when(certID1.getIssuerNameHash()).thenReturn(new byte[]{7, 8, 9});
        when(certID2.getIssuerNameHash()).thenReturn(new byte[]{10, 11, 12});
        when(certID1.getSerialNumber()).thenReturn(java.math.BigInteger.ONE);
        when(certID2.getSerialNumber()).thenReturn(java.math.BigInteger.TEN);

        // Call the method
        boolean result = (boolean) compareCertIDsMethod.invoke(ocspProvider, certID1, certID2);

        // Verify the result
        assertFalse(result, "Certificate IDs should not match");
    }
    
    /**
     * Test for the compareCertIDs method with identical certificate IDs.
     * This test covers the branch where the certificate IDs match.
     */
    @Test
    public void testCompareCertIDs_IdenticalCertIDs() throws Exception {
        // Get the compareCertIDs method
        Method compareCertIDsMethod = ZacsOCSPProvider.class.getDeclaredMethod(
                "compareCertIDs", JcaCertificateID.class, CertificateID.class);
        compareCertIDsMethod.setAccessible(true);

        // Create mocks
        JcaCertificateID certID1 = mock(JcaCertificateID.class);
        CertificateID certID2 = mock(CertificateID.class);

        // Set up the mocks with identical values
        byte[] keyHash = new byte[]{1, 2, 3};
        byte[] nameHash = new byte[]{4, 5, 6};
        java.math.BigInteger serialNumber = java.math.BigInteger.ONE;
        
        when(certID1.getIssuerKeyHash()).thenReturn(keyHash);
        when(certID2.getIssuerKeyHash()).thenReturn(keyHash);
        when(certID1.getIssuerNameHash()).thenReturn(nameHash);
        when(certID2.getIssuerNameHash()).thenReturn(nameHash);
        when(certID1.getSerialNumber()).thenReturn(serialNumber);
        when(certID2.getSerialNumber()).thenReturn(serialNumber);

        // Call the method
        boolean result = (boolean) compareCertIDsMethod.invoke(ocspProvider, certID1, certID2);

        // Verify the result
        assertTrue(result, "Certificate IDs should match");
    }
}