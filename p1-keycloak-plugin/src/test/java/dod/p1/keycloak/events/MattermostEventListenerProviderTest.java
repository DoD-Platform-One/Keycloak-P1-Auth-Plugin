package dod.p1.keycloak.events;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.HashSet;

import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.powermock.api.mockito.PowerMockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({
})
public class MattermostEventListenerProviderTest {

    @Mock private HashSet<EventType> excludedEvents;
    @Mock private HashSet<ResourceType> includedAdminEvents;
    private final String[] groups = {"group1", "group2", "group3"};
    private final String serverUri = "serverURI";
    @Mock private KeycloakSession session;
    @Mock private UserModel userModel;

    private MattermostEventListenerProvider provider;

    @Before
    public void setUp() {
        // mocks
        KeycloakContext keycloakContext = mock(KeycloakContext.class);
        UserProvider userProvider = mock(UserProvider.class);

        // keycloakSession
        when(session.getContext()).thenReturn(keycloakContext);
        when(session.users()).thenReturn(userProvider);
        when(session.users().getUserById(any(), any())).thenReturn(userModel);

    }

    @Test
    public void MattermostEventListenerProviderConstructorTest(){
        // Constructor
        provider = new MattermostEventListenerProvider(null, null, groups, serverUri, session);
        // check the constructor
        assertNotNull(provider);
    }

    @Test
    public void onEventEventTest(){
        // Condition 1
        // Mocks
        Event event = mock(Event.class);
        // Constructor
        provider = new MattermostEventListenerProvider(null, null, groups, serverUri, session);
        // check the constructor
        assertNotNull(provider);
        // onEvent
        provider.onEvent(event);

        // Condition 2
        // Constructor
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        // onEvent
        provider.onEvent(event);

        // Condition 3
        // condition
        when(excludedEvents.contains(any())).thenReturn(true);
        // Constructor
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        // onEvent
        provider.onEvent(event);

    }

    @Test
    public void onEventAdminEventTest(){
        // Condition 1
        // Mocks
        AdminEvent adminEvent = mock(AdminEvent.class);
        // Constructor
        provider = new MattermostEventListenerProvider(null, null, groups, serverUri, session);
        // check the constructor
        assertNotNull(provider);
        // onEvent
        provider.onEvent(adminEvent, true);

        // Condition 2
        // Mocks
        AuthDetails authDetails = mock(AuthDetails.class);
        // conditions
        when(adminEvent.getAuthDetails()).thenReturn(authDetails);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.CUSTOM);
        // Constructor
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        // onEvent
        provider.onEvent(adminEvent, true);

        // Condition 3
        // conditions
        when(includedAdminEvents.contains(any())).thenReturn(true);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP_MEMBERSHIP);
        // Constructor
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        // onEvent
        provider.onEvent(adminEvent, true);

        // Condition 4
        // conditions
        when(adminEvent.getRepresentation()).thenReturn("{ Representation: representation, path: path, name: name }");
        when(adminEvent.getError()).thenReturn("Error");
        when(adminEvent.getAuthDetails().getUserId()).thenReturn("UserId");
        when(adminEvent.getResourcePath()).thenReturn("ResourcePath/something1/something2/something3");
        // Constructor
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        // onEvent
        provider.onEvent(adminEvent, true);

        // Condition 5
        // conditions
        when(userModel.getUsername()).thenReturn("username");
        when(userModel.getEmail()).thenReturn("some@email");
        // Constructor
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        // onEvent
        provider.onEvent(adminEvent, true);

//        // Condition 6  - Slack is giving me a headache
//        // conditions
//        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP);
//        // Constructor
//        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
//        // onEvent
//        provider.onEvent(adminEvent, true);
    }

    @Test
    public void closeTest(){
        // Constructor
        provider = new MattermostEventListenerProvider(null, null, groups, serverUri, session);
        // check the constructor
        assertNotNull(provider);
        // onEvent
        provider.close();
    }
}
