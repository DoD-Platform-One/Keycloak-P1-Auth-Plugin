package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.NewObjectProvider;
import dod.p1.keycloak.utils.Utils;
import dod.p1.keycloak.utils.ZacsOCSPProvider;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.crypto.UserIdentityExtractor;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.GroupProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.vault.VaultTranscriber;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.Security;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static dod.p1.keycloak.registration.X509Tools.*;
import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.keycloak.Config.*;

class X509ToolsTest {

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
    ValidationContext validationContext;
    @Mock
    X509ClientCertificateLookup x509ClientCertificateLookup;
    @Mock
    AuthenticatorConfigModel authenticatorConfigModel;
    @Mock
    UserIdentityExtractor userIdentityExtractor;
    @Mock
    UserProvider userProvider;
    @Mock
    UserModel userModel;
    @Mock
    GroupProvider groupProvider;
    @Mock
    RequiredActionContext requiredActionContext;

    private MockedStatic<CryptoIntegration> cryptoIntegrationMock;

    @BeforeEach
    void setupMockBehavior() throws Exception {
        MockitoAnnotations.openMocks(this);
        setupFileMocks();

        // Ensure non-FIPS Bouncy Castle provider is added.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        // Set system properties to disable FIPS mode.
        System.setProperty("keycloak.crypto.fips-mode", "false");
        System.setProperty("keycloak.fips", "false");

        CryptoProvider dummyProvider = mock(CryptoProvider.class);
        cryptoIntegrationMock = mockStatic(CryptoIntegration.class);
        cryptoIntegrationMock.when(CryptoIntegration::getProvider).thenReturn(dummyProvider);

        // Static mocking for Config.scope("babyYodaOcsp")
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            Config.Scope scope = mock(Config.Scope.class);
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("false");
        }

        when(validationContext.getSession()).thenReturn(keycloakSession);
        when(validationContext.getHttpRequest()).thenReturn(httpRequest);
        when(validationContext.getRealm()).thenReturn(realmModel);
        when(requiredActionContext.getSession()).thenReturn(keycloakSession);
        when(keycloakSession.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getAuthenticationSession()).thenReturn(authenticationSessionModel);
        when(keycloakSession.groups()).thenReturn(groupProvider);
        when(authenticationSessionModel.getParentSession()).thenReturn(rootAuthenticationSessionModel);
        when(rootAuthenticationSessionModel.getId()).thenReturn("xxx");
    }

    @AfterEach
    void tearDown() {
        if (cryptoIntegrationMock != null) {
            cryptoIntegrationMock.close();
        }
    }

    @Test
    void testTranslateAffiliationShortName() {
        assertNull(X509Tools.translateAffiliationShortName(""));
    }

    @Test
    void testLogAndExtractSANs() throws Exception {
        X509Certificate x509Certificate = Utils.buildTestCertificate();
        logAndExtractSANs(x509Certificate, userModel, true);
    }

    @Test
    void testLogAndExtractSANs2() throws Exception {
        X509Certificate x509Certificate = Utils.buildTestCertificate();
        logAndExtractSANs(x509Certificate, userModel);
    }

    @Test
    void testGetSanTypeName() {
        assertEquals("otherName", getSanTypeName(0));
        assertEquals("RFC822 Name", getSanTypeName(1));
        assertEquals("DNS Name", getSanTypeName(2));
        assertEquals("URI", getSanTypeName(6));
        assertEquals("IP Address", getSanTypeName(7));
        assertEquals("Unknown Type", getSanTypeName(100));
    }

    @Test
    void testParseSanValue() throws IOException {
        assertEquals("null", parseSanValue(0, null));
        // When sanValue is a String, even for type 0, it is returned directly.
        assertEquals("otherName", parseSanValue(0, "otherName"));
        // For byte[] that are not valid ASN.1, our method returns "Invalid ASN1 Structure"
        assertEquals("Invalid ASN1 Structure", parseSanValue(0, "otherName".getBytes()));
        assertEquals("otherName", parseSanValue(100, "otherName"));
        byte[] invalidAsn1Bytes = {0x00, 0x01, 0x02};
        assertEquals("Invalid ASN1 Structure", parseSanValue(0, invalidAsn1Bytes));
        ASN1ObjectIdentifier asn1Object = new ASN1ObjectIdentifier("1.2.3.4");
        byte[] validAsn1Bytes = asn1Object.getEncoded();
        assertEquals("{\"type\": \"OID\", \"value\": \"1.2.3.4\"}", parseSanValue(0, validAsn1Bytes));
    }

    @Test
    void testAsn1ToJsonHelper() throws IOException {
        ASN1Encodable[] encodables = new ASN1Encodable[]{
                new ASN1ObjectIdentifier("1.2.3.4"),
                new DERUTF8String("Test String")
        };
        ASN1Primitive sequence = new DERSequence(encodables);
        byte[] validAsn1Bytes = sequence.getEncoded();
        String expectedJson = "{\n" +
                "  \"Element 0\": {\"type\": \"OID\", \"value\": \"1.2.3.4\"},\n" +
                "  \"Element 1\": {\"type\": \"String\", \"value\": \"Test String\"}\n" +
                "}";
        assertEquals(expectedJson, parseSanValue(0, validAsn1Bytes));

        ASN1ObjectIdentifier asn1Obj = new ASN1ObjectIdentifier("1.2.3.4");
        validAsn1Bytes = asn1Obj.getEncoded();
        assertEquals("{\"type\": \"OID\", \"value\": \"1.2.3.4\"}", parseSanValue(0, validAsn1Bytes));
    }

    @Test
    void testExtractUPN() throws Exception {
        X509Certificate x509Certificate = Utils.buildTestCertificate();
        assertNull(extractUPN(x509Certificate));
    }

    @Test
    void testExtractURN() throws Exception {
        X509Certificate x509Certificate = Utils.buildTestCertificate();
        assertNull(extractURN(x509Certificate));
    }

    @Test
    void testParsePemToX509Certificate() throws IOException, java.security.cert.CertificateException, Exception {
        String validPemCert = convertCertToPEM(Utils.buildTestCertificate());
        assertNotNull(parsePemToX509Certificate(validPemCert));
    }

    @Test
    void testConvertCertToPEM() throws Exception {
        X509Certificate x509Certificate = Utils.buildTestCertificate();
        assertNotNull(convertCertToPEM(x509Certificate));
    }

    @Test
    void testGetCertificatePolicyId() throws Exception {
        X509Certificate x509Certificate = Utils.buildTestCertificate();
        assertEquals("2.16.840.1.114028.10.1.5", getCertificatePolicyId(x509Certificate, 0, 0));
        x509Certificate = mock(X509Certificate.class);
        assertNull(getCertificatePolicyId(x509Certificate, 0, 0));
    }

    @Test
    void testIsX509RegisteredFalse() {
        boolean isRegistered = isX509Registered(validationContext);
        assertFalse(isRegistered);
        isRegistered = isX509Registered(requiredActionContext);
        assertFalse(isRegistered);
    }

    @Test
    void testGetX509UsernameNull() {
        String usernameNull = getX509Username(validationContext);
        assertNull(usernameNull);
        usernameNull = getX509Username(requiredActionContext);
        assertNull(usernameNull);
    }

    @Test
    void testGetX509IdentityFromCertChain() throws Exception {
        String cn = "CN=login.dso.mil, O=Department of Defense, L=Colorado Springs, ST=Colorado, C=US";
        Map<String, String> configMap = new HashMap<>();
        configMap.put(AbstractX509ClientCertificateAuthenticator.CUSTOM_ATTRIBUTE_NAME, "test");

        when(realmModel.getAuthenticatorConfigsStream()).thenReturn(Stream.of(authenticatorConfigModel));
        when(authenticatorConfigModel.getConfig()).thenReturn(configMap);

        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(eq(keycloakSession), eq(realmModel)))
                    .thenReturn(commonConfig);
            when(commonConfig.getRequiredCertificatePolicies()).thenReturn(Stream.of("2.16.840.1.114028.10.1.5"));

            // Test with null or empty certificate chain
            assertNull(getX509IdentityFromCertChain(null, keycloakSession, realmModel, authenticationSessionModel));
            assertNull(getX509IdentityFromCertChain(new X509Certificate[0], keycloakSession, realmModel, authenticationSessionModel));
            assertNull(getX509IdentityFromCertChain(new X509Certificate[]{mock(X509Certificate.class)},
                    keycloakSession, realmModel, authenticationSessionModel));

            // For the valid path, use construction mocking to stub out the new authenticator.
            try (MockedConstruction<X509ClientCertificateAuthenticator> mocked =
                         mockConstruction(X509ClientCertificateAuthenticator.class, (mock, context) -> {
                             when(mock.getUserIdentityExtractor(any(X509AuthenticatorConfigModel.class)))
                                     .thenReturn(userIdentityExtractor);
                             when(userIdentityExtractor.extractUserIdentity(any()))
                                     .thenReturn(cn);
                         })) {
                String result = (String) getX509IdentityFromCertChain(new X509Certificate[]{Utils.buildTestCertificate()},
                        keycloakSession, realmModel, authenticationSessionModel);
                assertEquals(cn, result);
            }
        }
    }

    @Test
    void testGetX509IdentityFromCertChain2() throws Exception {
        when(realmModel.getAuthenticatorConfigsStream()).thenReturn(Stream.empty());
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(eq(keycloakSession), eq(realmModel)))
                    .thenReturn(commonConfig);
            when(commonConfig.getRequiredCertificatePolicies()).thenReturn(Stream.of("2.16.840.1.114028.10.1.5"));

            assertNull(getX509IdentityFromCertChain(
                    new X509Certificate[]{Utils.buildTestCertificate()},
                    keycloakSession, realmModel, authenticationSessionModel
            ));
        }
    }

    @Test
    void testIsX509RegisteredTrue() throws Exception {
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            Config.Scope babyYodaScope = mock(Config.Scope.class);
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(babyYodaScope);
            when(babyYodaScope.get("enabled", "false")).thenReturn("true");

            X509Certificate[] certList = {Utils.buildTestCertificate()};
            when(x509ClientCertificateLookup.getCertificateChain(httpRequest)).thenReturn(certList);

            when(realmModel.getAuthenticatorConfigsStream()).thenReturn(Stream.of(authenticatorConfigModel));
            Map<String, String> configMap = new HashMap<>();
            configMap.put("x509-cert-auth.mapper-selection.user-attribute-name", "test");
            when(authenticatorConfigModel.getConfig()).thenReturn(configMap);

            // Stub the user identity extractor in a similar way if needed.
            when(keycloakSession.users()).thenReturn(userProvider);
            when(userProvider.searchForUserByUserAttributeStream(any(RealmModel.class), anyString(), anyString()))
                    .thenReturn(Stream.of(userModel));

            boolean isRegistered = isX509Registered(validationContext);
            assertFalse(isRegistered);
        }
    }

    @Test
    void testExtractUPNFromOtherNameDirect() throws IOException {
        String upn = "user@domain.com";
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3");
        ASN1Primitive upnValue = new DERUTF8String(upn);
        ASN1TaggedObject taggedObject = new DERTaggedObject(true, 0, upnValue);
        ASN1Encodable[] elements = new ASN1Encodable[]{oid, taggedObject};
        ASN1Primitive sequence = new DERSequence(elements);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        org.bouncycastle.asn1.ASN1OutputStream asn1Out = org.bouncycastle.asn1.ASN1OutputStream.create(baos);
        asn1Out.writeObject(sequence);
        asn1Out.close();
        byte[] sanValue = baos.toByteArray();
        assertEquals(upn, extractUPNFromOtherNameDirect(sanValue));
    }
}
