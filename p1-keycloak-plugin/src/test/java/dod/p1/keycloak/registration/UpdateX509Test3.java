package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.OCSPUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.security.GeneralSecurityException;
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
public class UpdateX509Test3 {

    @Mock
    private RequiredActionContext context;
    
    @Mock
    private KeycloakSession session;
    
    @Mock
    private RealmModel realm;
    
    @Mock
    private UserModel user;
    
    @Mock
    private GroupModel group;
    
    @Mock
    private AuthenticationSessionModel authSession;
    
    @Mock
    private HttpRequest httpRequest;
    
    @Mock
    private CommonConfig commonConfig;
    
    @Mock
    private Config.Scope scope;
    
    private UpdateX509 updateX509;

    @BeforeEach
    public void setUp() {
        updateX509 = new UpdateX509();
        
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        
        when(user.getUsername()).thenReturn("testuser");
    }

    @Test
    public void testIsDirectMemberOfGroupWithNullUser() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("isDirectMemberOfGroup", UserModel.class, GroupModel.class);
        method.setAccessible(true);
        
        // Test with null user
        boolean result = (boolean) method.invoke(updateX509, null, group);
        assertFalse(result);
    }

    @Test
    public void testIsDirectMemberOfGroupWithNullGroup() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("isDirectMemberOfGroup", UserModel.class, GroupModel.class);
        method.setAccessible(true);
        
        // Test with null group
        boolean result = (boolean) method.invoke(updateX509, user, null);
        assertFalse(result);
    }

    @Test
    public void testHandleUserRegistrationWhenNotRegistered() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleUserRegistration", RequiredActionContext.class, UserModel.class);
        method.setAccessible(true);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools.isX509Registered to return false
            x509ToolsMock.when(() -> X509Tools.isX509Registered(context)).thenReturn(false);
            
            // Call the method
            method.invoke(updateX509, context, user);
            
            // Verify that the required action was added
            verify(user).addRequiredAction("UPDATE_X509");
        }
    }

    @Test
    public void testHandleUserRegistrationWhenAlreadyRegistered() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleUserRegistration", RequiredActionContext.class, UserModel.class);
        method.setAccessible(true);
        
        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools.isX509Registered to return true
            x509ToolsMock.when(() -> X509Tools.isX509Registered(context)).thenReturn(true);
            
            // Call the method
            method.invoke(updateX509, context, user);
            
            // Verify that the required action was not added
            verify(user, never()).addRequiredAction("UPDATE_X509");
        }
    }

    @Test
    public void testHandleOCSPConfiguration() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleOCSPConfiguration");
        method.setAccessible(true);
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class)) {
            // Mock Config.scope to return a scope that returns "true" for "enabled"
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            
            // Call the method - should not throw exception
            assertDoesNotThrow(() -> method.invoke(updateX509));
        }
    }

    @Test
    public void testHandleActiveCAC_WithOCSPEnabled_AllConditionsMet() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleActiveCAC", 
            RequiredActionContext.class, UserModel.class, String.class);
        method.setAccessible(true);
        
        // Setup
        String x509Username = "x509user";
        when(authSession.getAuthNote("authenticated_via_x509")).thenReturn("true");
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Mock Config.scope to return a scope that returns "true" for "enabled"
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            
            // Mock X509Tools.isX509Registered to return true
            x509ToolsMock.when(() -> X509Tools.isX509Registered(context)).thenReturn(true);
            
            // Mock CommonConfig
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("x509_active");
            
            // Call the method
            boolean result = (boolean) method.invoke(updateX509, context, user, x509Username);
            
            // Verify result and attribute setting
            assertTrue(result);
            verify(user).setSingleAttribute("x509_active", x509Username);
        }
    }

    @Test
    public void testHandleActiveCAC_WithOCSPEnabled_ConditionsNotMet() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleActiveCAC", 
            RequiredActionContext.class, UserModel.class, String.class);
        method.setAccessible(true);
        
        // Setup
        String x509Username = "x509user";
        when(authSession.getAuthNote("authenticated_via_x509")).thenReturn("false");
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            
            // Mock Config.scope to return a scope that returns "true" for "enabled"
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("true");
            
            // Mock X509Tools.isX509Registered to return false
            x509ToolsMock.when(() -> X509Tools.isX509Registered(context)).thenReturn(false);
            
            // Call the method
            boolean result = (boolean) method.invoke(updateX509, context, user, x509Username);
            
            // Verify result and attribute removal
            assertFalse(result);
            // No longer removing ALLOW_X509 attribute;
        }
    }

    @Test
    public void testHandleActiveCAC_WithOCSPDisabled_ConditionsMet() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleActiveCAC", 
            RequiredActionContext.class, UserModel.class, String.class);
        method.setAccessible(true);
        
        // Setup
        String x509Username = "x509user";
        
        try (MockedStatic<Config> configMock = mockStatic(Config.class);
             MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            
            // Mock Config.scope to return a scope that returns "false" for "enabled"
            configMock.when(() -> Config.scope("babyYodaOcsp")).thenReturn(scope);
            when(scope.get("enabled", "false")).thenReturn("false");
            
            // Mock X509Tools.isX509Registered to return true
            x509ToolsMock.when(() -> X509Tools.isX509Registered(context)).thenReturn(true);
            
            // Mock CommonConfig
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getUserActive509Attribute()).thenReturn("x509_active");
            
            // Call the method
            boolean result = (boolean) method.invoke(updateX509, context, user, x509Username);
            
            // Verify result and attribute setting
            assertTrue(result);
            verify(user).setSingleAttribute("x509_active", x509Username);
        }
    }

    @Test
    public void testHandleGroupAssignments() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleGroupAssignments", 
            UserModel.class, RealmModel.class, KeycloakSession.class);
        method.setAccessible(true);
        
        // Setup
        when(group.getName()).thenReturn("x509-group");
        when(group.getId()).thenReturn("group-id");
        
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Mock CommonConfig
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of(group));
            
            // Mock user.getGroupsStream to return an empty stream (user not in group)
            when(user.getGroupsStream()).thenReturn(Stream.empty());
            
            // Call the method
            method.invoke(updateX509, user, realm, session);
            
            // Verify that the user joined the group
            verify(user).joinGroup(group);
        }
    }

    @Test
    public void testHandleGroupAssignments_UserAlreadyInGroup() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleGroupAssignments", 
            UserModel.class, RealmModel.class, KeycloakSession.class);
        method.setAccessible(true);
        
        // Setup
        when(group.getName()).thenReturn("x509-group");
        when(group.getId()).thenReturn("group-id");
        
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Mock CommonConfig
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of(group));
            
            // Mock user.getGroupsStream to return a stream with the group (user already in group)
            when(user.getGroupsStream()).thenReturn(Stream.of(group));
            
            // Call the method
            method.invoke(updateX509, user, realm, session);
            
            // Verify that the user did not join the group again
            verify(user, never()).joinGroup(group);
        }
    }

    @Test
    public void testHandleGroupAssignments_WithNullGroup() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleGroupAssignments", 
            UserModel.class, RealmModel.class, KeycloakSession.class);
        method.setAccessible(true);
        
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Mock CommonConfig
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of((GroupModel)null));
            
            // Call the method - should not throw exception
            assertDoesNotThrow(() -> method.invoke(updateX509, user, realm, session));
            
            // Verify that the user did not join any group
            verify(user, never()).joinGroup(any(GroupModel.class));
        }
    }

    @Test
    public void testHandleGroupAssignments_WithExceptionDuringJoin() throws Exception {
        // Use reflection to access the private method
        java.lang.reflect.Method method = UpdateX509.class.getDeclaredMethod("handleGroupAssignments", 
            UserModel.class, RealmModel.class, KeycloakSession.class);
        method.setAccessible(true);
        
        // Setup
        when(group.getName()).thenReturn("x509-group");
        when(group.getId()).thenReturn("group-id");
        
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Mock CommonConfig
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getAutoJoinGroupX509()).thenReturn(Stream.of(group));
            
            // Mock user.getGroupsStream to return an empty stream (user not in group)
            when(user.getGroupsStream()).thenReturn(Stream.empty());
            
            // Mock user.joinGroup to throw an exception
            doThrow(new RuntimeException("Test exception")).when(user).joinGroup(group);
            
            // Call the method - should not throw exception
            assertDoesNotThrow(() -> method.invoke(updateX509, user, realm, session));
        }
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
        // Should not throw exception
        assertDoesNotThrow(() -> updateX509.init(scope));
    }

    @Test
    public void testPostInit() {
        // Should not throw exception
        assertDoesNotThrow(() -> updateX509.postInit(mock(KeycloakSessionFactory.class)));
    }

    @Test
    public void testClose() {
        // Should not throw exception
        assertDoesNotThrow(() -> updateX509.close());
    }

    @Test
    public void testGetId() {
        assertEquals("UPDATE_X509", updateX509.getId());
    }
}