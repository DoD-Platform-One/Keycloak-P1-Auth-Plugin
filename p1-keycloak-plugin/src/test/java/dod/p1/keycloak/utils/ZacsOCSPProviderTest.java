package dod.p1.keycloak.utils;
//import org.junit.Test;
//import org.junit.runner.RunWith;
//import org.powermock.api.mockito.PowerMockito;
//import org.powermock.core.classloader.annotations.PrepareForTest;
//import org.keycloak.crypto.def.BCOCSPProvider;
//import org.keycloak.models.KeycloakSession;
//import org.powermock.modules.junit4.PowerMockRunner;
//
//import java.net.URI;
//import java.security.cert.CertPathValidatorException;
//import java.security.cert.CertificateEncodingException;
//import java.security.cert.X509Certificate;
//import java.util.Collections;
//import java.util.Date;
//import java.util.List;
//
//import static org.junit.Assert.assertNotNull;
//import static org.powermock.api.mockito.PowerMockito.mockStatic;
//
//@RunWith(PowerMockRunner.class)
//@PrepareForTest(BCOCSPProvider.class)
class ZacsOCSPProviderTest {

    // WHAT A PAIN TO TEST, need some drinks in order to deal with this one.

//    @Test
//    void checkTest() throws CertPathValidatorException {
//        // Arrange
//        mockStatic(BCOCSPProvider.class);
//
//        ZacsOCSPProvider zacsOCSPProvider = new ZacsOCSPProvider();
//
//        KeycloakSession session = PowerMockito.mock(KeycloakSession.class);
//        X509Certificate cert = PowerMockito.mock(X509Certificate.class);
//        X509Certificate issuerCertificate = PowerMockito.mock(X509Certificate.class);
//        List<URI> responderURIs = Collections.singletonList(URI.create("http://example.com"));
//        X509Certificate responderCert = PowerMockito.mock(X509Certificate.class);
//        Date date = new Date();
//
//        // Act & Assert
//        assertNotNull(zacsOCSPProvider.check(session, cert, issuerCertificate, responderURIs, responderCert, date));
//    }
//
//    @Test
//    void getResponderURIsTest() throws CertificateEncodingException {
//        // Arrange
//        mockStatic(BCOCSPProvider.class);
//
//        ZacsOCSPProvider zacsOCSPProvider = new ZacsOCSPProvider();
//
//        X509Certificate cert = PowerMockito.mock(X509Certificate.class);
//
//        // Act & Assert
//        assertNotNull(zacsOCSPProvider.getResponderURIs(cert));
//    }
//
//    @Test
//    void getResponderURIsPublicTest() throws CertificateEncodingException {
//        // Arrange
//        mockStatic(BCOCSPProvider.class);
//
//        ZacsOCSPProvider zacsOCSPProvider = new ZacsOCSPProvider();
//
//        X509Certificate cert = PowerMockito.mock(X509Certificate.class);
//
//        // Act & Assert
//        assertNotNull(zacsOCSPProvider.getResponderURIsPublic(cert));
//    }
}
