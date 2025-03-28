package dod.p1.keycloak.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.keycloak.email.DefaultEmailSenderProvider;
import org.keycloak.email.EmailException;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class WelcomeEmailEventListenerProviderTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private Event event;

    @BeforeEach
    public void setUp() {
        // Stub session.realms() to avoid NPE in provider constructor
        RealmProvider realmProvider = mock(RealmProvider.class);
        when(session.realms()).thenReturn(realmProvider);
    }

    @Test
    public void welcomeEmailEventListenerProviderDefault() {
        // Mocks for admin event
        AdminEvent adminEvent = Mockito.mock(AdminEvent.class);

        // Constructor
        WelcomeEmailEventListenerProvider welcomeEmailEventListenerProvider = 
            new WelcomeEmailEventListenerProvider(session);

        // check that constructor is not null
        assertNotNull(welcomeEmailEventListenerProvider);

        // onEvent with a simple event
        welcomeEmailEventListenerProvider.onEvent(event);

        // onEvent with an admin event
        welcomeEmailEventListenerProvider.onEvent(adminEvent, true);

        // close
        welcomeEmailEventListenerProvider.close();
    }

    @Test
    public void onEventConditions() {
        // Mocks for session dependencies
        RealmProvider realmProvider = mock(RealmProvider.class);
        UserProvider userProvider = mock(UserProvider.class);
        RealmModel realm = mock(RealmModel.class);
        UserModel userModel = mock(UserModel.class);
        Map<String, String> smtpConfig = new HashMap<>();

        // Stub required methods
        when(session.realms()).thenReturn(realmProvider);
        when(session.users()).thenReturn(userProvider);
        when(realmProvider.getRealm(anyString())).thenReturn(realm);
        when(event.getType()).thenReturn(EventType.VERIFY_EMAIL);
        when(event.getRealmId()).thenReturn("test-realm");
        when(event.getUserId()).thenReturn("user-123");
        when(realm.getSmtpConfig()).thenReturn(smtpConfig);

        // Create a spy of the provider to mock the createEmailSenderProvider method
        WelcomeEmailEventListenerProvider welcomeEmailEventListenerProvider =
            spy(new WelcomeEmailEventListenerProvider(session));
        
        // Mock the createEmailSenderProvider method to return our mock
        DefaultEmailSenderProvider emailSenderProvider = mock(DefaultEmailSenderProvider.class);
        doReturn(emailSenderProvider).when(welcomeEmailEventListenerProvider).createEmailSenderProvider(any(KeycloakSession.class));
        
        // Mock the send method to avoid EmailException
        try {
            doNothing().when(emailSenderProvider).send(any(Map.class), any(UserModel.class), anyString(), anyString(), anyString());
        } catch (EmailException e) {
            // This won't happen in the test since we're mocking the method
        }
        
        assertNotNull(welcomeEmailEventListenerProvider);

        // Test with null user
        when(userProvider.getUserById(any(RealmModel.class), anyString())).thenReturn(null);
        welcomeEmailEventListenerProvider.onEvent(event);

        // Test with user but null email
        when(userProvider.getUserById(any(RealmModel.class), anyString())).thenReturn(userModel);
        when(userModel.getEmail()).thenReturn(null);
        welcomeEmailEventListenerProvider.onEvent(event);

        // Test with user and non-mil email
        when(userModel.getEmail()).thenReturn("user@example.com");
        welcomeEmailEventListenerProvider.onEvent(event);

        // Test with user and mil email but welcome email already sent
        when(userModel.getEmail()).thenReturn("user@mail.mil");
        when(userModel.getFirstAttribute("welcomeEmailSent")).thenReturn("true");
        welcomeEmailEventListenerProvider.onEvent(event);

        // Test with user, mil email, no welcome email sent, but old account
        when(userModel.getFirstAttribute("welcomeEmailSent")).thenReturn(null);
        when(userModel.getCreatedTimestamp()).thenReturn(0L); // Very old timestamp
        welcomeEmailEventListenerProvider.onEvent(event);

        // Test with user, mil email, no welcome email sent, new account
        when(userModel.getCreatedTimestamp()).thenReturn(System.currentTimeMillis());
        when(realm.getName()).thenReturn("test-realm");
        when(realm.getDisplayName()).thenReturn("Test Realm");
        
        // Run the event
        welcomeEmailEventListenerProvider.onEvent(event);
        
        // Verify the attribute was set, which indicates the email was sent
        verify(userModel, times(1)).setSingleAttribute("welcomeEmailSent", "true");
    }
}