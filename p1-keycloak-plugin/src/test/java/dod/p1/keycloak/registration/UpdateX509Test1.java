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
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Additional test coverage for {@link UpdateX509} class.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class UpdateX509Test1 {

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
    public void testIsDirectMemberOfGroup() throws Exception {
        // Setup
        GroupModel group = mock(GroupModel.class);
        when(group.getId()).thenReturn("group-id");

        // Test with null user
        assertFalse(invokeIsDirectMemberOfGroup(null, group));

        // Test with null group
        assertFalse(invokeIsDirectMemberOfGroup(user, null));

        // Test with user not in group
        when(user.getGroupsStream()).thenReturn(Stream.empty());
        assertFalse(invokeIsDirectMemberOfGroup(user, group));

        // Test with user in group
        GroupModel userGroup = mock(GroupModel.class);
        when(userGroup.getId()).thenReturn("group-id");
        when(user.getGroupsStream()).thenReturn(Stream.of(userGroup));
        assertTrue(invokeIsDirectMemberOfGroup(user, group));
    }

    @Test
    public void testHandleActiveCAC_WithOCSPEnabled_AllConditionsMet() throws Exception {
        // Setup
        String x509Username = "test-x509-username";
        when(mockScope.get("enabled", "false")).thenReturn("true");
        when(authSession.getAuthNote("authenticated_via_x509")).thenReturn("true");

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {

            // Setup X509Tools mock
            x509ToolsMock.when(() -> X509Tools.isX509Registered(context)).thenReturn(true);

            // Setup CommonConfig mock
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");

            // Call the method
            boolean result = invokeHandleActiveCAC(context, user, x509Username);

            // Verify
            assertTrue(result);
            verify(user).setSingleAttribute("activeCAC", x509Username);
        }
    }

    @Test
    public void testHandleActiveCAC_WithOCSPEnabled_MissingConditions() throws Exception {
        // Setup
        String x509Username = "test-x509-username";
        when(mockScope.get("enabled", "false")).thenReturn("true");

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {

            // Setup X509Tools mock - not registered
            x509ToolsMock.when(() -> X509Tools.isX509Registered(context)).thenReturn(false);

            // Setup CommonConfig mock
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);

            // Call the method
            boolean result = invokeHandleActiveCAC(context, user, x509Username);

            // Verify
            assertFalse(result);
            // No longer removing ALLOW_X509 attribute;
            verify(user, never()).setSingleAttribute(anyString(), anyString());
        }
    }

    @Test
    public void testHandleActiveCAC_WithOCSPDisabled_AllConditionsMet() throws Exception {
        // Setup
        String x509Username = "test-x509-username";
        when(mockScope.get("enabled", "false")).thenReturn("false");

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {

            // Setup X509Tools mock
            x509ToolsMock.when(() -> X509Tools.isX509Registered(context)).thenReturn(true);

            // Setup CommonConfig mock
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("activeCAC");

            // Call the method
            boolean result = invokeHandleActiveCAC(context, user, x509Username);

            // Verify
            assertTrue(result);
            verify(user).setSingleAttribute("activeCAC", x509Username);
        }
    }

    @Test
    public void testExtractAndSetCertificateAttributes() throws Exception {
        // Setup
        X509Certificate cert = Utils.buildTestCertificate();

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Setup X509Tools mock
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(cert)).thenReturn("PEM-CERT");
            x509ToolsMock.when(() -> X509Tools.extractUPN(cert)).thenReturn("1234567890123456@mil");
            x509ToolsMock.when(() -> X509Tools.getCertificatePolicyId(cert, 0, 0)).thenReturn("test-policy-id");
            x509ToolsMock.when(() -> X509Tools.extractURN(cert)).thenReturn("test-urn");

            // Call the method
            invokeExtractAndSetCertificateAttributes(user, cert, session, realm);

            // Verify - don't use matchers for this test
            verify(user, atLeastOnce()).setSingleAttribute(anyString(), anyString());

            // Verify specific attributes
            verify(user).setSingleAttribute("x509_certificate", "PEM-CERT");
            verify(user).setSingleAttribute("x509_upn", "1234567890123456@mil");
            verify(user).setSingleAttribute("x509_piv", "1234567890123456");
            verify(user).setSingleAttribute("x509_policy_id", "test-policy-id");
            verify(user).setSingleAttribute("x509_urn", "test-urn");
        }
    }

    @Test
    public void testExtractAndSetCertificateAttributes_WithNullExtractedValues() throws Exception {
        // Setup
        X509Certificate cert = Utils.buildTestCertificate();

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Setup X509Tools mock
            x509ToolsMock.when(() -> X509Tools.convertCertToPEM(cert)).thenReturn("PEM-CERT");
            x509ToolsMock.when(() -> X509Tools.extractUPN(cert)).thenReturn(null);
            x509ToolsMock.when(() -> X509Tools.getCertificatePolicyId(cert, 0, 0)).thenReturn(null);
            x509ToolsMock.when(() -> X509Tools.extractURN(cert)).thenReturn(null);

            // Call the method
            invokeExtractAndSetCertificateAttributes(user, cert, session, realm);

            // Verify - don't use matchers for this test
            verify(user, atLeastOnce()).setSingleAttribute(anyString(), anyString());

            // Verify specific attributes
            verify(user).setSingleAttribute("x509_certificate", "PEM-CERT");
            verify(user, never()).setSingleAttribute(eq("x509_upn"), any());
            verify(user, never()).setSingleAttribute(eq("x509_piv"), any());
            verify(user, never()).setSingleAttribute(eq("x509_policy_id"), any());
            verify(user, never()).setSingleAttribute(eq("x509_urn"), any());
        }
    }

    @Test
    public void testHandleGroupAssignments() throws Exception {
        // Setup
        GroupModel group1 = mock(GroupModel.class);
        when(group1.getName()).thenReturn("group1");

        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup CommonConfig mock
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of(group1));

            // Setup user not in group
            when(user.getGroupsStream()).thenReturn(Stream.empty());

            // Call the method
            invokeHandleGroupAssignments(user, realm, session);

            // Verify
            verify(user).joinGroup(group1);
        }
    }

    @Test
    public void testHandleGroupAssignments_UserAlreadyInGroup() throws Exception {
        // Setup
        GroupModel group1 = mock(GroupModel.class);
        when(group1.getName()).thenReturn("group1");
        when(group1.getId()).thenReturn("group1-id");

        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup CommonConfig mock
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of(group1));

            // Setup user already in group
            when(user.getGroupsStream()).thenReturn(Stream.of(group1));

            // Call the method
            invokeHandleGroupAssignments(user, realm, session);

            // Verify
            verify(user, never()).joinGroup(any(GroupModel.class));
        }
    }

    @Test
    public void testHandleGroupAssignments_WithNullGroup() throws Exception {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup CommonConfig mock
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of((GroupModel) null));

            // Call the method
            invokeHandleGroupAssignments(user, realm, session);

            // Verify
            verify(user, never()).joinGroup(any(GroupModel.class));
        }
    }

    @Test
    public void testHandleCancellation() throws Exception {
        // Call the method
        invokeHandleCancellation(context);

        // Verify
        verify(authSession).setAuthNote("IGNORE_X509", "true");
        verify(context).success();
    }

    @Test
    public void testSetUserCACAttributes() throws Exception {
        // Setup
        String userIdentityAttribute = "userIdentityAttr";
        String userActive509Attribute = "activeCAC";
        String x509Username = "test-x509-username";

        // Call the method
        invokeSetUserCACAttributes(user, userIdentityAttribute, userActive509Attribute, x509Username);

        // Verify
        verify(user).setSingleAttribute(userIdentityAttribute, x509Username);
        verify(user).setSingleAttribute(userActive509Attribute, x509Username);
    }

    @Test
    public void testRequiredActionChallenge() {
        // Setup
        when(context.form()).thenReturn(loginFormsProvider);
        when(loginFormsProvider.createX509ConfirmPage()).thenReturn(response);

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Setup X509Tools mock
            x509ToolsMock.when(() -> X509Tools.getX509Username(context)).thenReturn("test-x509-username");

            // Call the method
            updateX509.requiredActionChallenge(context);

            // Verify
            verify(loginFormsProvider).setFormData(any(MultivaluedMap.class));
            verify(loginFormsProvider).createX509ConfirmPage();
            verify(context).challenge(response);
        }
    }

    @Test
    public void testProcessAction_WithCancellation() {
        // Setup
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        formData.add("cancel", "true");
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        // Call the method
        updateX509.processAction(context);

        // Verify
        verify(authSession).setAuthNote("IGNORE_X509", "true");
        verify(context).success();
    }

    @Test
    public void testProcessAction_WithNullUser() {
        // Setup
        when(context.getUser()).thenReturn(null);

        // Call the method
        updateX509.processAction(context);

        // Verify
        verify(context).failure();
    }

    @Test
    public void testGetDisplayText() {
        assertEquals("Update X509", updateX509.getDisplayText());
    }

    @Test
    public void testIsOneTimeAction() {
        assertTrue(updateX509.isOneTimeAction());
    }

    @Test
    public void testCreate() {
        assertSame(updateX509, updateX509.create(session));
    }

    @Test
    public void testInit() {
        Config.Scope scope = mock(Config.Scope.class);
        updateX509.init(scope);
        // No assertions needed, just verifying it doesn't throw
    }

    @Test
    public void testPostInit() {
        updateX509.postInit(sessionFactory);
        // No assertions needed, just verifying it doesn't throw
    }

    @Test
    public void testClose() {
        updateX509.close();
        // No assertions needed, just verifying it doesn't throw
    }

    @Test
    public void testGetId() {
        assertEquals("UPDATE_X509", updateX509.getId());
    }

    // Helper methods to invoke private methods using reflection

    private boolean invokeIsDirectMemberOfGroup(UserModel user, GroupModel group) throws Exception {
        return (boolean) invokePrivateMethod(updateX509, "isDirectMemberOfGroup",
                                           new Class<?>[]{UserModel.class, GroupModel.class},
                                           user, group);
    }

    private boolean invokeHandleActiveCAC(RequiredActionContext context, UserModel user, String x509Username) throws Exception {
        return (boolean) invokePrivateMethod(updateX509, "handleActiveCAC",
                                           new Class<?>[]{RequiredActionContext.class, UserModel.class, String.class},
                                           context, user, x509Username);
    }

    private void invokeExtractAndSetCertificateAttributes(UserModel user, X509Certificate cert,
                                                         KeycloakSession session, RealmModel realm) throws Exception {
        invokePrivateMethod(updateX509, "extractAndSetCertificateAttributes",
                           new Class<?>[]{UserModel.class, X509Certificate.class},
                           user, cert);
    }

    private void invokeHandleGroupAssignments(UserModel user, RealmModel realm, KeycloakSession session) throws Exception {
        invokePrivateMethod(updateX509, "handleGroupAssignments",
                          new Class<?>[]{UserModel.class, RealmModel.class, KeycloakSession.class},
                          user, realm, session);
    }

    private void invokeHandleCancellation(RequiredActionContext context) throws Exception {
        invokePrivateMethod(updateX509, "handleCancellation",
                          new Class<?>[]{RequiredActionContext.class},
                          context);
    }

    private void invokeSetUserCACAttributes(UserModel user, String userIdentityAttribute,
                                       String userActive509Attribute, String x509Username) throws Exception {
        invokePrivateMethod(updateX509, "setUserCACAttributes",
                          new Class<?>[]{UserModel.class, String.class, String.class, String.class},
                          user, userIdentityAttribute, userActive509Attribute, x509Username);
    }

    private void invokeHandleFinalSteps(RequiredActionContext context) throws Exception {
        invokePrivateMethod(updateX509, "handleFinalSteps",
                          new Class<?>[]{RequiredActionContext.class},
                          context);
    }

    private Object invokePrivateMethod(Object instance, String methodName, Class<?>[] paramTypes, Object... args) throws Exception {
        java.lang.reflect.Method method = instance.getClass().getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return method.invoke(instance, args);
    }
}
