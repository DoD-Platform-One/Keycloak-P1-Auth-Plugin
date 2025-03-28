package dod.p1.keycloak.utils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.truststore.TruststoreProvider;

import javax.security.auth.x500.X500Principal;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Additional tests to increase coverage for OCSPUtils.
 */
public class OCSPUtilsTest1 {

    private KeycloakSession keycloakSession;
    private RealmModel realmModel;
    private TruststoreProvider truststoreProvider;
    private KeyStore keyStore;
    private X500Principal issuerPrincipal;
    private String expectedSerialNumber;

    @BeforeEach
    public void setup() throws Exception {
        keycloakSession = mock(KeycloakSession.class);
        realmModel = mock(RealmModel.class);
        truststoreProvider = mock(TruststoreProvider.class);
        keyStore = mock(KeyStore.class);
        issuerPrincipal = new X500Principal("CN=Test, OU=ExampleOrg");
        expectedSerialNumber = "1234567890987654321";
    }

    @Test
    public void testGetIssuerSerialNumber_NullExtension() throws Exception {
        // Test that getIssuerSerialNumber returns null when certificate extension is missing.
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getExtensionValue("2.5.29.35")).thenReturn(null);

        Method method = OCSPUtils.class.getDeclaredMethod("getIssuerSerialNumber", X509Certificate.class);
        method.setAccessible(true);
        String serialNumber = (String) method.invoke(null, cert);

        assertNull(serialNumber, "Expected null if Authority Key Identifier extension is missing");
    }

    @Test
    public void testGetIssuerSerialNumber_InvalidExtension() throws Exception {
        // Test that getIssuerSerialNumber returns null when certificate extension bytes are invalid.
        X509Certificate cert = mock(X509Certificate.class);
        // Return some invalid bytes that won't parse as expected.
        when(cert.getExtensionValue("2.5.29.35")).thenReturn(new byte[]{0x01, 0x02});

        Method method = OCSPUtils.class.getDeclaredMethod("getIssuerSerialNumber", X509Certificate.class);
        method.setAccessible(true);
        String serialNumber = (String) method.invoke(null, cert);

        assertNull(serialNumber, "Expected null if the AKI extension cannot be parsed");
    }

    @Test
    public void testFindCAInTruststore_Positive() throws GeneralSecurityException {
        // Create a valid CA certificate mock that matches issuerPrincipal and expected serial number.
        X509Certificate caCert = mock(X509Certificate.class);
        when(caCert.getSubjectX500Principal()).thenReturn(issuerPrincipal);
        when(caCert.getSerialNumber()).thenReturn(new BigInteger(expectedSerialNumber));
        // Make sure checkValidity() passes.
        doNothing().when(caCert).checkValidity();

        // Prepare truststore maps with the valid CA certificate.
        Map<X500Principal, List<X509Certificate>> rootMap = Map.of(issuerPrincipal, List.of(caCert));
        Map<X500Principal, List<X509Certificate>> interMap = Map.of(); // empty map

        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        when(truststoreProvider.getRootCertificates()).thenReturn(rootMap);
        when(truststoreProvider.getIntermediateCertificates()).thenReturn(interMap);
        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);

        X509Certificate result = OCSPUtils.findCAInTruststore(keycloakSession, issuerPrincipal, expectedSerialNumber);
        assertNotNull(result, "Expected a valid CA certificate to be returned");
        assertEquals(caCert, result, "Returned certificate should match the expected CA certificate");
    }

    @Test
    public void testFindCAInTruststore_ExpiredCertificate() throws GeneralSecurityException {
        // Create a CA certificate mock that throws CertificateExpiredException when checkValidity() is invoked.
        X509Certificate caCert = mock(X509Certificate.class);
        when(caCert.getSubjectX500Principal()).thenReturn(issuerPrincipal);
        when(caCert.getSerialNumber()).thenReturn(new BigInteger(expectedSerialNumber));
        doThrow(new CertificateExpiredException("Expired")).when(caCert).checkValidity();

        Map<X500Principal, List<X509Certificate>> rootMap = Map.of(issuerPrincipal, List.of(caCert));
        Map<X500Principal, List<X509Certificate>> interMap = Map.of(); // empty map

        when(truststoreProvider.getTruststore()).thenReturn(keyStore);
        when(truststoreProvider.getRootCertificates()).thenReturn(rootMap);
        when(truststoreProvider.getIntermediateCertificates()).thenReturn(interMap);
        when(keycloakSession.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);

        X509Certificate result = OCSPUtils.findCAInTruststore(keycloakSession, issuerPrincipal, expectedSerialNumber);
        assertNull(result, "Expected null because the CA certificate is expired");
    }
}
