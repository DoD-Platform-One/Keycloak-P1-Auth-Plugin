package dod.p1.keycloak.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class LastLoginEventListenerProviderTest {

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
    public void LastLoginEventListenerProviderDefault() {
        // Mocks for admin event
        AdminEvent adminEvent = Mockito.mock(AdminEvent.class);

        // Constructor
        LastLoginEventListenerProvider lastLoginEventListenerProvider = new LastLoginEventListenerProvider(session);

        // check that constructor is not null
        assertNotNull(lastLoginEventListenerProvider);

        // onEvent with a simple event
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent with an admin event
        lastLoginEventListenerProvider.onEvent(adminEvent, true);

        // close
        lastLoginEventListenerProvider.close();
    }

    @Test
    public void onEventConditions() {
        // Mocks for session dependencies
        RealmProvider realmProvider = mock(RealmProvider.class);
        UserProvider userProvider = mock(UserProvider.class);
        UserModel userModel = mock(UserModel.class);
        Map<String, List<String>> userAttrs = mock(Map.class);

        // Stub required methods
        when(session.realms()).thenReturn(realmProvider);
        when(session.users()).thenReturn(userProvider);
        when(event.getType()).thenReturn(EventType.LOGIN);

        // Constructor
        LastLoginEventListenerProvider lastLoginEventListenerProvider = new LastLoginEventListenerProvider(session);
        assertNotNull(lastLoginEventListenerProvider);

        // onEvent first condition
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent second condition: provide a user for lookup
        when(userProvider.getUserById(any(), any())).thenReturn(userModel);
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent third condition: stub user attributes
        when(userModel.getAttributes()).thenReturn(userAttrs);
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent fourth condition: simulate attributes containing key
        when(userAttrs.containsKey(anyString())).thenReturn(true);
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent fifth condition: simulate attribute value with something present
        when(userAttrs.get(anyString())).thenReturn(List.of("something"));
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent sixth condition: simulate empty attribute list
        when(userAttrs.get(anyString())).thenReturn(List.of());
        lastLoginEventListenerProvider.onEvent(event);
    }
}
