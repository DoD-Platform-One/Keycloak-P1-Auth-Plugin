package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.Utils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Additional test coverage for {@link X509Tools} class.
 */
public class X509ToolsTest2 {

    @Mock
    KeycloakSession keycloakSession;
    @Mock
    KeycloakContext keycloakContext;
    @Mock
    AuthenticationSessionModel authenticationSessionModel;
    @Mock
    RootAuthenticationSessionModel rootAuthenticationSessionModel;
    @Mock
    HttpRequest httpRequest;
    @Mock
    RealmModel realmModel;
    @Mock
    FormContext formContext;
    @Mock
    RequiredActionContext requiredActionContext;
    @Mock
    X509ClientCertificateLookup x509ClientCertificateLookup;
    @Mock
    UserProvider userProvider;
    @Mock
    UserModel userModel;

    private MockedStatic<CryptoIntegration> cryptoIntegrationMock;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        // Ensure non-FIPS Bouncy Castle provider is added
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Set system properties to disable FIPS mode
        System.setProperty("keycloak.crypto.fips-mode", "false");
        System.setProperty("keycloak.fips", "false");

        CryptoProvider dummyProvider = mock(CryptoProvider.class);
        cryptoIntegrationMock = mockStatic(CryptoIntegration.class);
        cryptoIntegrationMock.when(CryptoIntegration::getProvider).thenReturn(dummyProvider);

        // Common mock setup
        when(formContext.getSession()).thenReturn(keycloakSession);
        when(formContext.getHttpRequest()).thenReturn(httpRequest);
        when(formContext.getRealm()).thenReturn(realmModel);

        when(requiredActionContext.getSession()).thenReturn(keycloakSession);
        when(requiredActionContext.getHttpRequest()).thenReturn(httpRequest);
        when(requiredActionContext.getRealm()).thenReturn(realmModel);

        when(keycloakSession.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
        when(authenticationSessionModel.getParentSession()).thenReturn(rootAuthenticationSessionModel);
        when(rootAuthenticationSessionModel.getId()).thenReturn("test-session-id");
    }

    @AfterEach
    void tearDown() {
        if (cryptoIntegrationMock != null) {
            cryptoIntegrationMock.close();
        }
    }

    @Test
    void testExtractUPNWithValidUPN() throws CertificateParsingException {
        // Create a mock certificate with a UPN SAN
        X509Certificate cert = mock(X509Certificate.class);

        // Create a collection of SANs
        Collection<List<?>> sans = new ArrayList<>();

        // Add an otherName SAN (type 0) for UPN
        List<Object> otherNameSan = new ArrayList<>();
        otherNameSan.add(0); // otherName type
        otherNameSan.add(new byte[] {48, 34, 6, 10, 43, 6, 1, 4, 1, -126, 55, 20, 2, 3, -96, 20, 12, 18, 117, 115, 101, 114, 64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109}); // UPN ASN.1 structure
        sans.add(otherNameSan);

        when(cert.getSubjectAlternativeNames()).thenReturn(sans);

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Allow the real method to be called
            x509ToolsMock.when(() -> X509Tools.extractUPN(any(X509Certificate.class)))
                .thenCallRealMethod();

            // Mock the extractUPNFromOtherNameDirect method to return a test UPN
            x509ToolsMock.when(() -> X509Tools.extractUPNFromOtherNameDirect(any(byte[].class)))
                .thenReturn("user@example.com");

            // Should return the UPN
            assertEquals("user@example.com", X509Tools.extractUPN(cert));
        }
    }

    @Test
    void testExtractUPNWithNoUPN() throws CertificateParsingException {
        // Create a mock certificate with SANs but no UPN
        X509Certificate cert = mock(X509Certificate.class);

        // Create a collection of SANs
        Collection<List<?>> sans = new ArrayList<>();

        // Add a DNS SAN (type 2)
        List<Object> dnsSan = new ArrayList<>();
        dnsSan.add(2); // DNS type
        dnsSan.add("example.com");
        sans.add(dnsSan);

        when(cert.getSubjectAlternativeNames()).thenReturn(sans);

        // Should return null
        assertNull(X509Tools.extractUPN(cert));
    }

    @Test
    void testGetCertificatePolicyId() throws Exception {
        // Create a mock certificate
        X509Certificate cert = mock(X509Certificate.class);

        // Mock the certificate to return null for the extension value
        // Use a specific OID instead of anyString()
        when(cert.getExtensionValue("2.5.29.32")).thenReturn(null);

        // Test with null extension value
        assertNull(X509Tools.getCertificatePolicyId(cert, 0, 0));

        // Test with invalid indices - these should return null without throwing exceptions
        assertNull(X509Tools.getCertificatePolicyId(cert, -1, 0));
        assertNull(X509Tools.getCertificatePolicyId(cert, 0, -1));
    }

    @Test
    void testConvertCertToPEM() throws Exception {
        // Create a mock certificate
        X509Certificate cert = Utils.buildTestCertificate();

        // Test conversion to PEM
        String pem = X509Tools.convertCertToPEM(cert);
        assertNotNull(pem);
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"));
        assertTrue(pem.endsWith("-----END CERTIFICATE-----\n"));
    }

    @Test
    void testExtractUPNFromOtherNameDirect() throws IOException {
        // Create a valid UPN otherName structure
        String upn = "user@example.com";
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3");
        ASN1Primitive upnValue = new DERUTF8String(upn);
        ASN1TaggedObject taggedObject = new DERTaggedObject(true, 0, upnValue);
        ASN1Encodable[] elements = new ASN1Encodable[]{oid, taggedObject};
        ASN1Primitive sequence = new DERSequence(elements);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream asn1Out = ASN1OutputStream.create(baos);
        asn1Out.writeObject(sequence);
        asn1Out.close();
        byte[] sanValue = baos.toByteArray();

        // Should extract the UPN
        assertEquals(upn, X509Tools.extractUPNFromOtherNameDirect(sanValue));
    }

    @Test
    void testExtractUPNFromOtherNameDirectWithInvalidOID() throws IOException {
        // Create an otherName structure with wrong OID
        String upn = "user@example.com";
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.2.3.4"); // Wrong OID
        ASN1Primitive upnValue = new DERUTF8String(upn);
        ASN1TaggedObject taggedObject = new DERTaggedObject(true, 0, upnValue);
        ASN1Encodable[] elements = new ASN1Encodable[]{oid, taggedObject};
        ASN1Primitive sequence = new DERSequence(elements);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ASN1OutputStream asn1Out = ASN1OutputStream.create(baos);
        asn1Out.writeObject(sequence);
        asn1Out.close();
        byte[] sanValue = baos.toByteArray();

        // Should return null due to wrong OID
        assertNull(X509Tools.extractUPNFromOtherNameDirect(sanValue));
    }

    @Test
    void testGetSanTypeName() {
        // Test all SAN type names
        assertEquals("otherName", X509Tools.getSanTypeName(0));
        assertEquals("RFC822 Name", X509Tools.getSanTypeName(1));
        assertEquals("DNS Name", X509Tools.getSanTypeName(2));
        assertEquals("URI", X509Tools.getSanTypeName(6));
        assertEquals("IP Address", X509Tools.getSanTypeName(7));
        assertEquals("Unknown Type", X509Tools.getSanTypeName(100));
    }

    @Test
    void testParseSanValue() {
        // Test with null value
        assertEquals("null", X509Tools.parseSanValue(0, null));

        // Test with string value
        assertEquals("test", X509Tools.parseSanValue(1, "test"));
        assertEquals("test", X509Tools.parseSanValue(2, "test"));
        assertEquals("test", X509Tools.parseSanValue(6, "test"));
        assertEquals("test", X509Tools.parseSanValue(7, "test"));
        assertEquals("test", X509Tools.parseSanValue(100, "test"));

        // For otherName type, just verify it doesn't throw an exception
        // and returns a non-null value
        try {
            // Create a simple ASN.1 structure that won't cause parsing errors
            ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.2.3.4");
            ASN1Encodable[] elements = new ASN1Encodable[]{oid};
            ASN1Primitive sequence = new DERSequence(elements);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ASN1OutputStream asn1Out = ASN1OutputStream.create(baos);
            asn1Out.writeObject(sequence);
            asn1Out.close();
            byte[] sanBytes = baos.toByteArray();

            String result = X509Tools.parseSanValue(0, sanBytes);
            assertNotNull(result);
        } catch (IOException e) {
            fail("Failed to create ASN.1 structure: " + e.getMessage());
        }
    }

    @Test
    void testExtractURNWithValidURN() throws CertificateParsingException {
        // Create a mock certificate with a URN SAN
        X509Certificate cert = mock(X509Certificate.class);

        // Create a collection of SANs
        Collection<List<?>> sans = new ArrayList<>();

        // Add a URI SAN (type 6)
        List<Object> uriSan = new ArrayList<>();
        uriSan.add(6); // URI type
        uriSan.add("urn:example:12345");
        sans.add(uriSan);

        when(cert.getSubjectAlternativeNames()).thenReturn(sans);

        // Should return the URN
        assertEquals("urn:example:12345", X509Tools.extractURN(cert));
    }

    @Test
    void testExtractURNWithNoURN() throws CertificateParsingException {
        // Create a mock certificate with SANs but no URN
        X509Certificate cert = mock(X509Certificate.class);

        // Create a collection of SANs
        Collection<List<?>> sans = new ArrayList<>();

        // Add a DNS SAN (type 2)
        List<Object> dnsSan = new ArrayList<>();
        dnsSan.add(2); // DNS type
        dnsSan.add("example.com");
        sans.add(dnsSan);

        when(cert.getSubjectAlternativeNames()).thenReturn(sans);

        // Should return null
        assertNull(X509Tools.extractURN(cert));
    }

    @Test
    void testLogAndExtractSANsWithNullSANs() throws CertificateParsingException {
        // Create a mock certificate with null SANs
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSubjectAlternativeNames()).thenReturn(null);

        // This should not throw an exception
        X509Tools.logAndExtractSANs(cert, userModel);

        // Verify no attributes were set
        verify(userModel, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void testLogAndExtractSANsWithValidSANs() throws CertificateParsingException {
        // Create a mock certificate with some SANs
        X509Certificate cert = mock(X509Certificate.class);

        // Create a collection of SANs
        Collection<List<?>> sans = new ArrayList<>();

        // Add a DNS SAN (type 2)
        List<Object> dnsSan = new ArrayList<>();
        dnsSan.add(2); // DNS type
        dnsSan.add("example.com");
        sans.add(dnsSan);

        // Add an email SAN (type 1)
        List<Object> emailSan = new ArrayList<>();
        emailSan.add(1); // Email type
        emailSan.add("user@example.com");
        sans.add(emailSan);

        when(cert.getSubjectAlternativeNames()).thenReturn(sans);

        // Call the method
        X509Tools.logAndExtractSANs(cert, userModel);

        // Verify attributes were set
        verify(userModel).setSingleAttribute("x509_altname_1", "example.com");
        verify(userModel).setSingleAttribute("x509_altname_2", "user@example.com");
    }

    @Test
    void testLogAndExtractSANsWithExtractUPN() throws CertificateParsingException {
        // Create a mock certificate with some SANs
        X509Certificate cert = mock(X509Certificate.class);

        // Create a collection of SANs
        Collection<List<?>> sans = new ArrayList<>();

        // Add an otherName SAN (type 0) for UPN
        List<Object> otherNameSan = new ArrayList<>();
        otherNameSan.add(0); // otherName type
        otherNameSan.add(new byte[] {48, 34, 6, 10, 43, 6, 1, 4, 1, -126, 55, 20, 2, 3, -96, 20, 12, 18, 117, 115, 101, 114, 64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109}); // UPN ASN.1 structure
        sans.add(otherNameSan);

        when(cert.getSubjectAlternativeNames()).thenReturn(sans);

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Allow the real method to be called
            x509ToolsMock.when(() -> X509Tools.logAndExtractSANs(any(X509Certificate.class), any(UserModel.class), anyBoolean()))
                .thenCallRealMethod();

            // Mock the extractUPNFromOtherNameDirect method to return a test UPN
            x509ToolsMock.when(() -> X509Tools.extractUPNFromOtherNameDirect(any(byte[].class)))
                .thenReturn("user@example.com");

            // Mock the parseSanValue method to return a test value
            x509ToolsMock.when(() -> X509Tools.parseSanValue(anyInt(), any()))
                .thenReturn("test-san-value");

            // Call the method with extractUpn=true
            X509Tools.logAndExtractSANs(cert, userModel, true);

            // Verify attributes were set
            verify(userModel).setSingleAttribute("x509_altname_1", "test-san-value");
            verify(userModel).setSingleAttribute("x509_upn", "user@example.com");
            //verify(userModel).setSingleAttribute("x509_piv", "user");
            verify(userModel, never()).setSingleAttribute(eq("x509_piv"), any());
        }
    }

    @Test
    void testTranslateAffiliationShortName() {
        try (MockedStatic<CacAffiliations> cacAffiliationsMock = mockStatic(CacAffiliations.class)) {
            cacAffiliationsMock.when(() -> CacAffiliations.getLongName("USAF")).thenReturn("US Air Force");

            assertEquals("US Air Force", X509Tools.translateAffiliationShortName("USAF"));

            // Verify the method was called
            cacAffiliationsMock.verify(() -> CacAffiliations.getLongName("USAF"));
        }
    }

    @Test
    void testParsePemToX509Certificate() throws Exception {
        // Create a mock certificate
        X509Certificate cert = Utils.buildTestCertificate();
        String pem = X509Tools.convertCertToPEM(cert);

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Allow the real method to be called
            x509ToolsMock.when(() -> X509Tools.parsePemToX509Certificate(anyString()))
                .thenCallRealMethod();

            // Mock the convertCertToPEM method to return the test PEM
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(any(X509Certificate.class)))
                .thenReturn(pem);

            // Call the method with invalid PEM
            assertThrows(CertificateParsingException.class, () -> X509Tools.parsePemToX509Certificate("invalid-pem"));
        }
    }
}
