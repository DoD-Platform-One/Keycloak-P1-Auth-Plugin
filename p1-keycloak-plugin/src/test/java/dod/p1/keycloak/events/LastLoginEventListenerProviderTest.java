package dod.p1.keycloak.events;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.*;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({})
public class LastLoginEventListenerProviderTest {

    @Mock private KeycloakSession session;
    @Mock private Event event;

    @Test
    public void LastLoginEventListenerProviderDefault(){
        // Mocks
        AdminEvent adminEvent = mock(AdminEvent.class);

        // Constructor
        LastLoginEventListenerProvider lastLoginEventListenerProvider = new LastLoginEventListenerProvider(session);

        // check that constructor is not null
        assertNotNull(lastLoginEventListenerProvider);

        // onEvent (1)
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent (2)
        lastLoginEventListenerProvider.onEvent(adminEvent, true);

        // close
        lastLoginEventListenerProvider.close();
    }

    @Test
    public void onEventConditions(){
        // Mocks
        RealmProvider realmProvider = mock(RealmProvider.class);
        UserProvider userProvider = mock(UserProvider.class);
        UserModel userModel = mock(UserModel.class);
        Map<String, List<String>> userAttrs = mock(Map.class);

        // mock conditions
        when(session.realms()).thenReturn(realmProvider);
        when(session.users()).thenReturn(userProvider);
        when(event.getType()).thenReturn(EventType.LOGIN);

        // Constructor
        LastLoginEventListenerProvider lastLoginEventListenerProvider = new LastLoginEventListenerProvider(session);

        // check that constructor is not null
        assertNotNull(lastLoginEventListenerProvider);

        // onEvent first condition
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent second condition
        when(session.users().getUserById(any(), any())).thenReturn(userModel);
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent third condition
        when(userModel.getAttributes()).thenReturn(userAttrs);
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent fourth condition
        when(userAttrs.containsKey(anyString())).thenReturn(true);
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent fifth condition
        when(userAttrs.get(anyString())).thenReturn(List.of("something"));
        lastLoginEventListenerProvider.onEvent(event);

        // onEvent six condition
        when(userAttrs.get(anyString())).thenReturn(List.of());
        lastLoginEventListenerProvider.onEvent(event);
    }
}
