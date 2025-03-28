package dod.p1.keycloak.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class LastLoginEventListenerProviderTest1 {

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmProvider realmProvider;

    @Mock
    private UserProvider userProvider;

    @Mock
    private RealmModel realmModel;

    @Mock
    private UserModel userModel;

    @Mock
    private Event event;

    @Mock
    private AdminEvent adminEvent;

    @BeforeEach
    public void setUp() {
        // Stub session.realms() to avoid NPE in provider constructor
        when(session.realms()).thenReturn(realmProvider);
        when(session.users()).thenReturn(userProvider);
        
        // Stub realm and user lookups
        when(realmProvider.getRealm(anyString())).thenReturn(realmModel);
        when(userProvider.getUserById(any(RealmModel.class), anyString())).thenReturn(userModel);
    }

    @Test
    public void testOnEventWithNonLoginEvent() {
        // Setup a non-LOGIN event
        when(event.getType()).thenReturn(EventType.LOGOUT);
        
        // Create provider
        LastLoginEventListenerProvider provider = new LastLoginEventListenerProvider(session);
        
        // Call onEvent with non-LOGIN event
        provider.onEvent(event);
        
        // Verify that user attributes are not accessed for non-LOGIN events
        verify(userModel, never()).getAttributes();
        verify(userModel, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    public void testOnEventWithLoginEventAndNullUser() {
        // Setup a LOGIN event
        when(event.getType()).thenReturn(EventType.LOGIN);
        when(event.getRealmId()).thenReturn("test-realm");
        when(event.getUserId()).thenReturn("user-123");
        
        // Return null for user lookup to test null user handling
        when(userProvider.getUserById(any(RealmModel.class), anyString())).thenReturn(null);
        
        // Create provider
        LastLoginEventListenerProvider provider = new LastLoginEventListenerProvider(session);
        
        // Call onEvent with LOGIN event and null user
        provider.onEvent(event);
        
        // Verify that user attributes are not accessed for null user
        verify(userModel, never()).getAttributes();
        verify(userModel, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    public void testOnEventWithLoginEventAndEmptyLastLoginAttribute() {
        // Setup a LOGIN event
        when(event.getType()).thenReturn(EventType.LOGIN);
        when(event.getRealmId()).thenReturn("test-realm");
        when(event.getUserId()).thenReturn("user-123");
        
        // Setup user attributes with empty lastlogin list
        Map<String, List<String>> attributes = new HashMap<>();
        List<String> emptyList = new ArrayList<>();
        attributes.put("lastlogin", emptyList);
        when(userModel.getAttributes()).thenReturn(attributes);
        
        // Create provider
        LastLoginEventListenerProvider provider = new LastLoginEventListenerProvider(session);
        
        // Call onEvent with LOGIN event and empty lastlogin attribute
        provider.onEvent(event);
        
        // Verify that priorlogin is not set but lastlogin is set
        verify(userModel, never()).setSingleAttribute(eq("priorlogin"), anyString());
        verify(userModel, times(1)).setSingleAttribute(eq("lastlogin"), anyString());
    }

    @Test
    public void testOnEventWithLoginEventAndMultipleLastLoginValues() {
        // Setup a LOGIN event
        when(event.getType()).thenReturn(EventType.LOGIN);
        when(event.getRealmId()).thenReturn("test-realm");
        when(event.getUserId()).thenReturn("user-123");
        
        // Setup user attributes with multiple lastlogin values
        Map<String, List<String>> attributes = new HashMap<>();
        List<String> lastLoginValues = new ArrayList<>();
        lastLoginValues.add("2023-01-01T12:00:00Z");
        lastLoginValues.add("2023-01-02T12:00:00Z");
        attributes.put("lastlogin", lastLoginValues);
        when(userModel.getAttributes()).thenReturn(attributes);
        
        // Create provider
        LastLoginEventListenerProvider provider = new LastLoginEventListenerProvider(session);
        
        // Call onEvent with LOGIN event and multiple lastlogin values
        provider.onEvent(event);
        
        // Verify that priorlogin is set to the first value and lastlogin is updated
        verify(userModel, times(1)).setSingleAttribute(eq("priorlogin"), eq("2023-01-01T12:00:00Z"));
        verify(userModel, times(1)).setSingleAttribute(eq("lastlogin"), anyString());
    }

    @Test
    public void testOnEventWithLoginEventAndNoExistingLastLoginAttribute() {
        // Setup a LOGIN event
        when(event.getType()).thenReturn(EventType.LOGIN);
        when(event.getRealmId()).thenReturn("test-realm");
        when(event.getUserId()).thenReturn("user-123");
        
        // Setup user attributes without lastlogin
        Map<String, List<String>> attributes = new HashMap<>();
        when(userModel.getAttributes()).thenReturn(attributes);
        
        // Create provider
        LastLoginEventListenerProvider provider = new LastLoginEventListenerProvider(session);
        
        // Call onEvent with LOGIN event and no existing lastlogin attribute
        provider.onEvent(event);
        
        // Verify that priorlogin is not set but lastlogin is set
        verify(userModel, never()).setSingleAttribute(eq("priorlogin"), anyString());
        verify(userModel, times(1)).setSingleAttribute(eq("lastlogin"), anyString());
    }

    @Test
    public void testOnAdminEventDoesNothing() {
        // Create provider
        LastLoginEventListenerProvider provider = new LastLoginEventListenerProvider(session);
        
        // Call onEvent with admin event
        provider.onEvent(adminEvent, true);
        
        // Verify that no user attributes are accessed or modified
        verify(userModel, never()).getAttributes();
        verify(userModel, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    public void testCloseDoesNothing() {
        // Create provider
        LastLoginEventListenerProvider provider = new LastLoginEventListenerProvider(session);
        
        // Call close
        provider.close();
        
        // No assertions needed as close is empty, but we're ensuring code coverage
    }
}