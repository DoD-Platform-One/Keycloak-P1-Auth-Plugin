package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.OCSPUtils;
import dod.p1.keycloak.utils.Utils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Additional test coverage for {@link UpdateX509} class focusing on certificate attribute extraction
 * and error handling paths.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class UpdateX509Test5 {

    @Mock
    private RequiredActionContext context;
    
    @Mock
    private KeycloakSession session;
    
    @Mock
    private KeycloakContext keycloakContext;
    
    @Mock
    private RealmModel realm;
    
    @Mock
    private UserModel user;
    
    @Mock
    private HttpRequest httpRequest;
    
    @Mock
    private AuthenticationSessionModel authSession;
    
    @Mock
    private LoginFormsProvider loginFormsProvider;
    
    private UpdateX509 updateX509;
    private MockedStatic<Config> configMock;
    private Config.Scope mockScope;

    @BeforeEach
    public void setUp() {
        updateX509 = new UpdateX509();
        
        // Setup common mocks
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getAuthenticationSession()).thenReturn(authSession);
        when(user.getUsername()).thenReturn("testuser");
        
        // Setup Config.scope mock
        configMock = Mockito.mockStatic(Config.class);
        mockScope = Mockito.mock(Config.Scope.class);
        configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(mockScope);
        when(mockScope.get("enabled", "false")).thenReturn("false");
    }

    @AfterEach
    public void tearDown() {
        if (configMock != null) {
            configMock.close();
        }
    }

    @Test
    public void testExtractAndSetCertificateAttributes_WithCertificateEncodingException() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            x509ToolsMock.when(() -> X509Tools.isX509Registered(any(RequiredActionContext.class)))
                    .thenReturn(true);
            
            // Setup CommonConfig
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock certificate attribute extraction
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(any(X509Certificate.class)))
                    .thenThrow(new CertificateEncodingException("Test encoding exception"));
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle CertificateEncodingException gracefully
            verify(user, never()).setSingleAttribute(eq("x509_certificate"), anyString());
            // Should set the activeCAC attribute
            verify(user).setSingleAttribute(eq("activeCAC"), eq(x509Username));
        }
    }

    @Test
    public void testExtractAndSetCertificateAttributes_WithRuntimeException() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            x509ToolsMock.when(() -> X509Tools.isX509Registered(any(RequiredActionContext.class)))
                    .thenReturn(true);
            
            // Setup CommonConfig
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock convertCertToPEM to throw RuntimeException
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(any(X509Certificate.class)))
                    .thenThrow(new RuntimeException("Test runtime exception"));
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle RuntimeException gracefully
            verify(user, never()).setSingleAttribute(eq("x509_certificate"), anyString());
            // Should set the activeCAC attribute
            verify(user).setSingleAttribute(eq("activeCAC"), eq(x509Username));
        }
    }

    @Test
    public void testExtractAndSetCertificateAttributes_WithNullUPN() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            x509ToolsMock.when(() -> X509Tools.isX509Registered(any(RequiredActionContext.class)))
                    .thenReturn(true);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock certificate attribute extraction
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(any(X509Certificate.class)))
                    .thenReturn("PEM-CERT");
            x509ToolsMock.when(() -> X509Tools.extractUPN(any(X509Certificate.class)))
                    .thenReturn(null);
            x509ToolsMock.when(() -> X509Tools.getCertificatePolicyId(any(X509Certificate.class), anyInt(), anyInt()))
                    .thenReturn("test-policy-id");
            x509ToolsMock.when(() -> X509Tools.extractURN(any(X509Certificate.class)))
                    .thenReturn("test-urn");
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle null UPN gracefully
            verify(user).setSingleAttribute(eq("x509_certificate"), eq("PEM-CERT"));
            verify(user, never()).setSingleAttribute(eq("x509_upn"), anyString());
            verify(user).setSingleAttribute(eq("x509_policy_id"), eq("test-policy-id"));
            verify(user).setSingleAttribute(eq("x509_urn"), eq("test-urn"));
        }
    }

    @Test
    public void testExtractAndSetCertificateAttributes_WithNullPolicyId() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            x509ToolsMock.when(() -> X509Tools.isX509Registered(any(RequiredActionContext.class)))
                    .thenReturn(true);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock certificate attribute extraction
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(any(X509Certificate.class)))
                    .thenReturn("PEM-CERT");
            x509ToolsMock.when(() -> X509Tools.extractUPN(any(X509Certificate.class)))
                    .thenReturn("test-upn");
            x509ToolsMock.when(() -> X509Tools.getCertificatePolicyId(any(X509Certificate.class), anyInt(), anyInt()))
                    .thenReturn(null);
            x509ToolsMock.when(() -> X509Tools.extractURN(any(X509Certificate.class)))
                    .thenReturn("test-urn");
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle null policy ID gracefully
            verify(user).setSingleAttribute(eq("x509_certificate"), eq("PEM-CERT"));
            verify(user).setSingleAttribute(eq("x509_upn"), eq("test-upn"));
            verify(user, never()).setSingleAttribute(eq("x509_policy_id"), anyString());
            verify(user).setSingleAttribute(eq("x509_urn"), eq("test-urn"));
        }
    }

    @Test
    public void testExtractAndSetCertificateAttributes_WithNullURN() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            x509ToolsMock.when(() -> X509Tools.isX509Registered(any(RequiredActionContext.class)))
                    .thenReturn(true);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock certificate attribute extraction
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(any(X509Certificate.class)))
                    .thenReturn("PEM-CERT");
            x509ToolsMock.when(() -> X509Tools.extractUPN(any(X509Certificate.class)))
                    .thenReturn("test-upn");
            x509ToolsMock.when(() -> X509Tools.getCertificatePolicyId(any(X509Certificate.class), anyInt(), anyInt()))
                    .thenReturn("test-policy-id");
            x509ToolsMock.when(() -> X509Tools.extractURN(any(X509Certificate.class)))
                    .thenReturn(null);
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle null URN gracefully
            verify(user).setSingleAttribute(eq("x509_certificate"), eq("PEM-CERT"));
            verify(user).setSingleAttribute(eq("x509_upn"), eq("test-upn"));
            verify(user).setSingleAttribute(eq("x509_policy_id"), eq("test-policy-id"));
            verify(user, never()).setSingleAttribute(eq("x509_urn"), anyString());
        }
    }

    @Test
    public void testExtractAndSetCertificateAttributes_WithAllAttributesNull() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            x509ToolsMock.when(() -> X509Tools.isX509Registered(any(RequiredActionContext.class)))
                    .thenReturn(true);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock certificate attribute extraction - all return null
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(any(X509Certificate.class)))
                    .thenReturn("PEM-CERT");
            x509ToolsMock.when(() -> X509Tools.extractUPN(any(X509Certificate.class)))
                    .thenReturn(null);
            x509ToolsMock.when(() -> X509Tools.getCertificatePolicyId(any(X509Certificate.class), anyInt(), anyInt()))
                    .thenReturn(null);
            x509ToolsMock.when(() -> X509Tools.extractURN(any(X509Certificate.class)))
                    .thenReturn(null);
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle all null attributes gracefully
            verify(user).setSingleAttribute(eq("x509_certificate"), eq("PEM-CERT"));
            verify(user, never()).setSingleAttribute(eq("x509_upn"), anyString());
            verify(user, never()).setSingleAttribute(eq("x509_policy_id"), anyString());
            verify(user, never()).setSingleAttribute(eq("x509_urn"), anyString());
        }
    }

    @Test
    public void testExtractAndSetCertificateAttributes_WithPolicyIdException() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            x509ToolsMock.when(() -> X509Tools.isX509Registered(any(RequiredActionContext.class)))
                    .thenReturn(true);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock certificate attribute extraction
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(any(X509Certificate.class)))
                    .thenReturn("PEM-CERT");
            x509ToolsMock.when(() -> X509Tools.extractUPN(any(X509Certificate.class)))
                    .thenReturn("test-upn");
            
            // Since getCertificatePolicyId returns a String and not void, we use when().thenThrow()
            x509ToolsMock.when(() -> X509Tools.getCertificatePolicyId(any(X509Certificate.class), anyInt(), anyInt()))
                .thenThrow(new IOException("Test policy ID exception"));
            
            x509ToolsMock.when(() -> X509Tools.extractURN(any(X509Certificate.class)))
                    .thenReturn("test-urn");
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle policy ID exception gracefully
            verify(user).setSingleAttribute(eq("activeCAC"), eq(x509Username));
            verify(user).setSingleAttribute(eq("x509_certificate"), eq("PEM-CERT"));
            verify(user).setSingleAttribute(eq("x509_upn"), eq("test-upn"));
            // Should not verify policy ID since it throws an exception
            verify(user, never()).setSingleAttribute(eq("x509_policy_id"), anyString());
        }
    }
}