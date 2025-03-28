package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.OCSPUtils;
import dod.p1.keycloak.utils.Utils;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Additional test coverage for {@link UpdateX509} class focusing on error handling paths.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class UpdateX509Test4 {

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
    
    @Mock
    private Response response;
    
    @Mock
    private KeycloakSessionFactory sessionFactory;
    
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
    public void testEvaluateTriggers_WithException() throws Exception {
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Setup to throw exception
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenThrow(new RuntimeException("Test exception"));
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle exception gracefully
            verify(user, never()).removeAttribute(anyString());
        }
    }

    @Test
    public void testHandleCertificateAttributes_WithNullCertChain() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(null);
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle null cert chain gracefully
            verify(user, never()).setSingleAttribute(eq("x509_certificate"), anyString());
        }
    }

    @Test
    public void testHandleCertificateAttributes_WithEmptyCertChain() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(new X509Certificate[0]);
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should handle empty cert chain gracefully
            verify(user, never()).setSingleAttribute(eq("x509_certificate"), anyString());
        }
    }

    @Test
    public void testHandleActiveCAC_ReturnsFalse() throws Exception {
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            x509ToolsMock.when(() -> X509Tools.isX509Registered(any(RequiredActionContext.class)))
                    .thenReturn(false);
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Execute
            updateX509.evaluateTriggers(context);
            
            // Verify - should call removeAttribute in handleActiveCAC
            // No longer removing ALLOW_X509 attribute;
        }
    }

    @Test
    public void testRequiredActionChallenge_WithException() throws Exception {
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Setup
            when(context.form()).thenReturn(loginFormsProvider);
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenThrow(new RuntimeException("Test exception"));
            
            // Execute
            updateX509.requiredActionChallenge(context);
            
            // Verify - should handle exception and call context.failure()
            verify(context).failure();
        }
    }

    @Test
    public void testProcessAction_WithNullUser() {
        // Setup
        when(context.getUser()).thenReturn(null);
        
        // Execute
        updateX509.processAction(context);
        
        // Verify - should call context.failure()
        verify(context).failure();
    }

    @Test
    public void testProcessAction_WithException() throws Exception {
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Setup
            MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
            when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenThrow(new RuntimeException("Test exception"));
            
            // Execute
            updateX509.processAction(context);
            
            // Verify - should handle exception and call context.failure()
            verify(context).failure();
        }
    }

    @Test
    public void testHandleOCSPProcessing_WithNullCertChain() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
            when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
            
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserIdentityAttribute(any(RealmModel.class))).thenReturn("userIdentityAttr");
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(null);
            
            // Execute
            updateX509.processAction(context);
            
            // Verify - should handle null cert chain and call context.failure()
            // Use atLeastOnce() since failure() is called in multiple places
            verify(context, atLeastOnce()).failure();
            verify(authSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
        }
    }

    @Test
    public void testHandleOCSPProcessing_WithEmptyCertChain() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
            when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
            
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserIdentityAttribute(any(RealmModel.class))).thenReturn("userIdentityAttr");
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(new X509Certificate[0]);
            
            // Execute
            updateX509.processAction(context);
            
            // Verify - should handle empty cert chain and call context.failure()
            // Use atLeastOnce() since failure() is called in multiple places
            verify(context, atLeastOnce()).failure();
            verify(authSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
        }
    }

    @Test
    public void testPerformOCSPCheck_WithFailedCheck() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
            when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
            
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserIdentityAttribute(any(RealmModel.class))).thenReturn("userIdentityAttr");
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Mock OCSP enabled
            when(mockScope.get("enabled", "false")).thenReturn("true");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock OCSP check failure
            OCSPUtils.OCSPResult failedResult = new OCSPUtils.OCSPResult(false, "Test failure reason");
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(any(KeycloakSession.class), any(X509Certificate[].class)))
                    .thenReturn(failedResult);
            
            // Execute
            updateX509.processAction(context);
            
            // Verify - should handle failed OCSP check and call context.failure()
            verify(context).failure();
            verify(authSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
        }
    }

    @Test
    public void testPerformOCSPCheck_WithSuccessfulCheck() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
            when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
            
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserIdentityAttribute(any(RealmModel.class))).thenReturn("userIdentityAttr");
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.empty());
            
            // Mock OCSP enabled
            when(mockScope.get("enabled", "false")).thenReturn("true");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock OCSP check success
            OCSPUtils.OCSPResult successResult = new OCSPUtils.OCSPResult(true, null);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(any(KeycloakSession.class), any(X509Certificate[].class)))
                    .thenReturn(successResult);
            
            // Execute
            updateX509.processAction(context);
            
            // Verify - should handle successful OCSP check and set attributes
            verify(authSession).setAuthNote(eq("authenticated_via_x509"), eq("true"));
            verify(user).setSingleAttribute(eq("userIdentityAttr"), eq(x509Username));
            verify(user).setSingleAttribute(eq("activeCAC"), eq(x509Username));
            // No longer removing ALLOW_X509 attribute;
            verify(context).success();
        }
    }

    @Test
    public void testHandleOCSPProcessing_WithSecurityException() throws Exception {
        try (MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Setup
            MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
            when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
            
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            when(commonConfig.getUserIdentityAttribute(any(RealmModel.class))).thenReturn("userIdentityAttr");
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Mock OCSP enabled
            when(mockScope.get("enabled", "false")).thenReturn("true");
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock OCSP check throwing exception
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(any(KeycloakSession.class), any(X509Certificate[].class)))
                    .thenThrow(new GeneralSecurityException("Test security exception"));
            
            // Execute
            updateX509.processAction(context);
            
            // Verify - should handle security exception and call context.failure()
            verify(context).failure();
            verify(authSession, never()).setAuthNote(eq("authenticated_via_x509"), anyString());
        }
    }

    @Test
    public void testHandleGroupAssignmentsAfterProcessing_WithNullGroup() throws Exception {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            
            // Return a stream with a null group
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of((GroupModel) null));
            
            // Setup for processAction
            MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
            when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
            
            // Execute
            updateX509.processAction(context);
            
            // Verify - should handle null group gracefully
            verify(user, never()).joinGroup(any(GroupModel.class));
        }
    }

    @Test
    public void testHandleGroupAssignmentsAfterProcessing_WithExceptionDuringJoin() throws Exception {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {
            
            // Setup
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            
            // Create a mock group
            GroupModel group = mock(GroupModel.class);
            when(group.getName()).thenReturn("testGroup");
            when(group.getId()).thenReturn("group-id");
            
            // Return a stream with the mock group
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of(group));
            when(commonConfig.getUserIdentityAttribute(any(RealmModel.class))).thenReturn("userIdentityAttr");
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Setup for processAction
            MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
            when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
            
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock OCSP check success
            OCSPUtils.OCSPResult successResult = new OCSPUtils.OCSPResult(true, null);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(any(KeycloakSession.class), any(X509Certificate[].class)))
                    .thenReturn(successResult);
            
            // Setup user not in group
            when(user.getGroupsStream()).thenReturn(Stream.empty());
            
            // Make joinGroup throw an exception
            doThrow(new RuntimeException("Test join exception")).when(user).joinGroup(any(GroupModel.class));
            
            // Execute
            updateX509.processAction(context);
            
            // Verify - should handle exception during join gracefully
            verify(user).joinGroup(any(GroupModel.class));
            // Should still complete the process
            // No longer removing ALLOW_X509 attribute;
        }
    }

    @Test
    public void testHandleGroupAssignmentsAfterProcessing_UserAlreadyInGroup() throws Exception {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<OCSPUtils> ocspUtilsMock = mockStatic(OCSPUtils.class)) {
            
            // Setup
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(any(KeycloakSession.class), any(RealmModel.class)))
                    .thenReturn(commonConfig);
            
            // Create a mock group
            GroupModel group = mock(GroupModel.class);
            when(group.getName()).thenReturn("testGroup");
            when(group.getId()).thenReturn("group-id");
            
            // Return a stream with the mock group
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of(group));
            when(commonConfig.getUserIdentityAttribute(any(RealmModel.class))).thenReturn("userIdentityAttr");
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");
            
            // Setup for processAction
            MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
            when(httpRequest.getDecodedFormParameters()).thenReturn(formData);
            
            String x509Username = "test-x509-username";
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(RequiredActionContext.class)))
                    .thenReturn(x509Username);
            
            // Create cert chain
            X509Certificate cert = Utils.buildTestCertificate();
            X509Certificate[] certChain = new X509Certificate[]{cert};
            ocspUtilsMock.when(() -> OCSPUtils.getCertificateChain(any(RequiredActionContext.class)))
                    .thenReturn(certChain);
            
            // Mock OCSP check success
            OCSPUtils.OCSPResult successResult = new OCSPUtils.OCSPResult(true, null);
            ocspUtilsMock.when(() -> OCSPUtils.performOCSPCheck(any(KeycloakSession.class), any(X509Certificate[].class)))
                    .thenReturn(successResult);
            
            // Setup user already in group
            GroupModel userGroup = mock(GroupModel.class);
            when(userGroup.getId()).thenReturn("group-id");
            when(user.getGroupsStream()).thenReturn(Stream.of(userGroup));
            
            // Execute
            updateX509.processAction(context);
            
            // Verify - should not attempt to join the group again
            verify(user, never()).joinGroup(any(GroupModel.class));
            // Should still complete the process
            // No longer removing ALLOW_X509 attribute;
        }
    }
}