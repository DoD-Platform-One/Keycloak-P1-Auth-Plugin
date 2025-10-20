package dod.p1.keycloak.events;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.common.YAMLConfig;
import dod.p1.keycloak.common.YAMLConfigMattermostProvisioning;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Unit tests for MattermostProvisioningEventListenerProvider.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MattermostProvisioningEventListenerProviderTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext context;

    @Mock
    private RealmModel realm;

    @Mock
    private UserProvider userProvider;

    @Mock
    private UserModel user;

    @Mock
    private Event event;

    @Mock
    private AdminEvent adminEvent;

    private MattermostProvisioningEventListenerProvider provider;

    @BeforeEach
    void setUp() {
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(userProvider);
    }

    @Test
    void testConstructor_WithValidConfig() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup mock config
            CommonConfig commonConfig = mock(CommonConfig.class);
            YAMLConfigMattermostProvisioning mattermostConfig = new YAMLConfigMattermostProvisioning();
            mattermostConfig.setEnabled(true);
            
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenReturn(commonConfig);
            when(commonConfig.getMattermostProvisioningConfig()).thenReturn(mattermostConfig);

            // Create provider
            provider = new MattermostProvisioningEventListenerProvider(session);

            // Verify provider is created
            assertNotNull(provider);
        }
    }

    @Test
    void testConstructor_WithNullConfig() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            CommonConfig commonConfig = mock(CommonConfig.class);
            
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenReturn(commonConfig);
            when(commonConfig.getMattermostProvisioningConfig()).thenReturn(null);

            // Create provider
            provider = new MattermostProvisioningEventListenerProvider(session);

            // Verify provider is created with default config
            assertNotNull(provider);
        }
    }

    @Test
    void testConstructor_WithException() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenThrow(new RuntimeException("Config error"));

            // Create provider
            provider = new MattermostProvisioningEventListenerProvider(session);

            // Verify provider is created with default config
            assertNotNull(provider);
        }
    }

    @Test
    void testConstructor_WithNullRealm() {
        when(context.getRealm()).thenReturn(null);

        // Create provider
        provider = new MattermostProvisioningEventListenerProvider(session);

        // Verify provider is created with default config
        assertNotNull(provider);
    }

    @Test
    void testOnEvent_ConfigDisabled() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup disabled config
            CommonConfig commonConfig = mock(CommonConfig.class);
            YAMLConfigMattermostProvisioning mattermostConfig = new YAMLConfigMattermostProvisioning();
            mattermostConfig.setEnabled(false);
            
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenReturn(commonConfig);
            when(commonConfig.getMattermostProvisioningConfig()).thenReturn(mattermostConfig);

            provider = new MattermostProvisioningEventListenerProvider(session);

            // Setup event
            when(event.getType()).thenReturn(EventType.VERIFY_EMAIL);

            // Call onEvent
            provider.onEvent(event);

            // Verify no user lookup happens
            verify(session.users(), never()).getUserById(any(), any());
        }
    }

    @Test
    void testOnEvent_NoEnvironmentsConfigured() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup config with no environments
            CommonConfig commonConfig = mock(CommonConfig.class);
            YAMLConfigMattermostProvisioning mattermostConfig = new YAMLConfigMattermostProvisioning();
            mattermostConfig.setEnabled(true);
            mattermostConfig.setEnvironments(new HashMap<>());
            
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenReturn(commonConfig);
            when(commonConfig.getMattermostProvisioningConfig()).thenReturn(mattermostConfig);

            provider = new MattermostProvisioningEventListenerProvider(session);

            // Setup event
            when(event.getType()).thenReturn(EventType.VERIFY_EMAIL);

            // Call onEvent
            provider.onEvent(event);

            // Verify no user lookup happens
            verify(session.users(), never()).getUserById(any(), any());
        }
    }

    @Test
    void testOnEvent_VerifyEmailEvent() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup config with environments
            CommonConfig commonConfig = mock(CommonConfig.class);
            YAMLConfigMattermostProvisioning mattermostConfig = new YAMLConfigMattermostProvisioning();
            mattermostConfig.setEnabled(true);
            
            Map<String, YAMLConfigMattermostProvisioning.MattermostEnvironment> environments = new HashMap<>();
            YAMLConfigMattermostProvisioning.MattermostEnvironment il2Env = 
                    new YAMLConfigMattermostProvisioning.MattermostEnvironment();
            il2Env.setEnabled(true);
            il2Env.setProvisionUrl("https://chat.il2.dso.mil/provision");
            il2Env.setProvisionToken("test-token");
            environments.put("IL2", il2Env);
            mattermostConfig.setEnvironments(environments);
            
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenReturn(commonConfig);
            when(commonConfig.getMattermostProvisioningConfig()).thenReturn(mattermostConfig);

            provider = new MattermostProvisioningEventListenerProvider(session);

            // Setup event
            when(event.getType()).thenReturn(EventType.VERIFY_EMAIL);
            when(event.getRealmId()).thenReturn("test-realm");
            when(event.getUserId()).thenReturn("test-user-id");

            // Setup realm and user
            when(session.realms()).thenReturn(mock(org.keycloak.models.RealmProvider.class));
            when(session.realms().getRealm("test-realm")).thenReturn(realm);
            when(userProvider.getUserById(realm, "test-user-id")).thenReturn(user);

            // Setup user attributes
            when(user.getUsername()).thenReturn("test.user");
            when(user.getEmail()).thenReturn("test@example.com");
            when(user.getFirstName()).thenReturn("Test");
            when(user.getLastName()).thenReturn("User");
            when(user.getId()).thenReturn("test-user-id");
            when(user.getFirstAttribute("mattermost_provisioned")).thenReturn(null);
            when(user.getFirstAttribute("persona")).thenReturn("101-AMC-fltcrew");

            // Call onEvent (Note: actual HTTP call will fail, but we're testing the flow)
            provider.onEvent(event);

            // Verify user lookup happened
            verify(session.realms()).getRealm("test-realm");
            verify(userProvider).getUserById(realm, "test-user-id");
            verify(user).getFirstAttribute("persona");
        }
    }

    @Test
    void testOnEvent_UserAlreadyProvisioned() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup config
            CommonConfig commonConfig = mock(CommonConfig.class);
            YAMLConfigMattermostProvisioning mattermostConfig = new YAMLConfigMattermostProvisioning();
            mattermostConfig.setEnabled(true);
            Map<String, YAMLConfigMattermostProvisioning.MattermostEnvironment> environments = new HashMap<>();
            environments.put("IL2", new YAMLConfigMattermostProvisioning.MattermostEnvironment());
            mattermostConfig.setEnvironments(environments);
            
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenReturn(commonConfig);
            when(commonConfig.getMattermostProvisioningConfig()).thenReturn(mattermostConfig);

            provider = new MattermostProvisioningEventListenerProvider(session);

            // Setup event
            when(event.getType()).thenReturn(EventType.VERIFY_EMAIL);
            when(event.getRealmId()).thenReturn("test-realm");
            when(event.getUserId()).thenReturn("test-user-id");

            // Setup realm and user
            when(session.realms()).thenReturn(mock(org.keycloak.models.RealmProvider.class));
            when(session.realms().getRealm("test-realm")).thenReturn(realm);
            when(userProvider.getUserById(realm, "test-user-id")).thenReturn(user);

            // User already provisioned
            when(user.getFirstAttribute("mattermost_provisioned")).thenReturn("true");
            when(user.getUsername()).thenReturn("test.user");

            // Call onEvent
            provider.onEvent(event);

            // Verify no persona check happens
            verify(user, never()).getFirstAttribute("persona");
        }
    }

    @Test
    void testOnEvent_UserWithoutPersona() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup config
            CommonConfig commonConfig = mock(CommonConfig.class);
            YAMLConfigMattermostProvisioning mattermostConfig = new YAMLConfigMattermostProvisioning();
            mattermostConfig.setEnabled(true);
            Map<String, YAMLConfigMattermostProvisioning.MattermostEnvironment> environments = new HashMap<>();
            environments.put("IL2", new YAMLConfigMattermostProvisioning.MattermostEnvironment());
            mattermostConfig.setEnvironments(environments);
            
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenReturn(commonConfig);
            when(commonConfig.getMattermostProvisioningConfig()).thenReturn(mattermostConfig);

            provider = new MattermostProvisioningEventListenerProvider(session);

            // Setup event
            when(event.getType()).thenReturn(EventType.VERIFY_EMAIL);
            when(event.getRealmId()).thenReturn("test-realm");
            when(event.getUserId()).thenReturn("test-user-id");

            // Setup realm and user
            when(session.realms()).thenReturn(mock(org.keycloak.models.RealmProvider.class));
            when(session.realms().getRealm("test-realm")).thenReturn(realm);
            when(userProvider.getUserById(realm, "test-user-id")).thenReturn(user);

            // User without persona
            when(user.getFirstAttribute("mattermost_provisioned")).thenReturn(null);
            when(user.getFirstAttribute("persona")).thenReturn(null);
            when(user.getUsername()).thenReturn("test.user");

            // Call onEvent
            provider.onEvent(event);

            // Verify no further processing
            verify(user, never()).getEmail();
        }
    }

    @Test
    void testOnEvent_RegisterEvent() {
        provider = new MattermostProvisioningEventListenerProvider(session);

        // Setup event with different type
        when(event.getType()).thenReturn(EventType.REGISTER);

        // Call onEvent
        provider.onEvent(event);

        // Verify no processing happens
        verify(session, never()).realms();
    }

    @Test
    void testOnEvent_RealmNotFound() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup config
            CommonConfig commonConfig = mock(CommonConfig.class);
            YAMLConfigMattermostProvisioning mattermostConfig = new YAMLConfigMattermostProvisioning();
            mattermostConfig.setEnabled(true);
            Map<String, YAMLConfigMattermostProvisioning.MattermostEnvironment> environments = new HashMap<>();
            environments.put("IL2", new YAMLConfigMattermostProvisioning.MattermostEnvironment());
            mattermostConfig.setEnvironments(environments);
            
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenReturn(commonConfig);
            when(commonConfig.getMattermostProvisioningConfig()).thenReturn(mattermostConfig);

            provider = new MattermostProvisioningEventListenerProvider(session);

            // Setup event
            when(event.getType()).thenReturn(EventType.VERIFY_EMAIL);
            when(event.getRealmId()).thenReturn("test-realm");

            // Realm not found
            when(session.realms()).thenReturn(mock(org.keycloak.models.RealmProvider.class));
            when(session.realms().getRealm("test-realm")).thenReturn(null);

            // Call onEvent
            provider.onEvent(event);

            // Verify no user lookup
            verify(session.users(), never()).getUserById(any(), any());
        }
    }

    @Test
    void testOnEvent_UserNotFound() {
        try (MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {
            // Setup config
            CommonConfig commonConfig = mock(CommonConfig.class);
            YAMLConfigMattermostProvisioning mattermostConfig = new YAMLConfigMattermostProvisioning();
            mattermostConfig.setEnabled(true);
            Map<String, YAMLConfigMattermostProvisioning.MattermostEnvironment> environments = new HashMap<>();
            environments.put("IL2", new YAMLConfigMattermostProvisioning.MattermostEnvironment());
            mattermostConfig.setEnvironments(environments);
            
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm))
                    .thenReturn(commonConfig);
            when(commonConfig.getMattermostProvisioningConfig()).thenReturn(mattermostConfig);

            provider = new MattermostProvisioningEventListenerProvider(session);

            // Setup event
            when(event.getType()).thenReturn(EventType.VERIFY_EMAIL);
            when(event.getRealmId()).thenReturn("test-realm");
            when(event.getUserId()).thenReturn("test-user-id");

            // Setup realm but user not found
            when(session.realms()).thenReturn(mock(org.keycloak.models.RealmProvider.class));
            when(session.realms().getRealm("test-realm")).thenReturn(realm);
            when(userProvider.getUserById(realm, "test-user-id")).thenReturn(null);

            // Call onEvent
            provider.onEvent(event);

            // Verify no further processing
            verify(user, never()).getFirstAttribute(any());
        }
    }

    @Test
    void testOnAdminEvent() {
        provider = new MattermostProvisioningEventListenerProvider(session);

        // Call onEvent with AdminEvent
        provider.onEvent(adminEvent, true);

        // Nothing should happen (method is empty)
        verifyNoInteractions(adminEvent);
    }

    @Test
    void testClose() {
        // Setup mock to create provider
        when(context.getRealm()).thenReturn(null);
        provider = new MattermostProvisioningEventListenerProvider(session);

        // Call close
        provider.close();

        // The close method is empty, just verify it doesn't throw
        // Session will have been accessed during construction
        verify(session).getContext();
    }
}