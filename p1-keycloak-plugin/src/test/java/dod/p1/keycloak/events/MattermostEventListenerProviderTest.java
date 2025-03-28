package dod.p1.keycloak.events;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class MattermostEventListenerProviderTest {

    @Mock
    private HashSet<EventType> excludedEvents;

    @Mock
    private HashSet<ResourceType> includedAdminEvents;

    private final String[] groups = {"group1", "group2", "group3"};
    private final String serverUri = "serverURI";

    @Mock
    private KeycloakSession session;

    @Mock
    private UserModel userModel;

    private MattermostEventListenerProvider provider;

    @BeforeEach
    public void setUp() {
        // Stub session context and user provider to prevent NPEs.
        KeycloakContext keycloakContext = mock(KeycloakContext.class);
        UserProvider userProvider = mock(UserProvider.class);
        when(session.getContext()).thenReturn(keycloakContext);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.getUserById(any(), any())).thenReturn(userModel);
    }

    @Test
    public void MattermostEventListenerProviderConstructorTest() {
        // Constructor test using provided parameters.
        provider = new MattermostEventListenerProvider(null, null, groups, serverUri, session);
        assertNotNull(provider);
    }

    @Test
    public void onEventEventTest() {
        // Condition 1: simple event
        Event event = mock(Event.class);
        provider = new MattermostEventListenerProvider(null, null, groups, serverUri, session);
        assertNotNull(provider);
        provider.onEvent(event);

        // Condition 2: using excluded events
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        provider.onEvent(event);

        // Condition 3: when excluded events contain the event type
        when(excludedEvents.contains(any())).thenReturn(true);
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        provider.onEvent(event);
    }

    @Test
    public void onEventAdminEventTest() {
        // Condition 1: basic admin event
        AdminEvent adminEvent = mock(AdminEvent.class);
        provider = new MattermostEventListenerProvider(null, null, groups, serverUri, session);
        assertNotNull(provider);
        provider.onEvent(adminEvent, true);

        // Condition 2: with auth details and non-standard resource type
        AuthDetails authDetails = mock(AuthDetails.class);
        when(adminEvent.getAuthDetails()).thenReturn(authDetails);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.CUSTOM);
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        provider.onEvent(adminEvent, true);

        // Condition 3: with included admin events and GROUP_MEMBERSHIP
        when(includedAdminEvents.contains(any())).thenReturn(true);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP_MEMBERSHIP);
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        provider.onEvent(adminEvent, true);

        // Condition 4: admin event with representation and error set
        when(adminEvent.getRepresentation()).thenReturn(
                "{ Representation: representation, path: path, name: name, username: username, email: email, clientId: clientId }"
        );
        when(adminEvent.getError()).thenReturn("Error");
        when(authDetails.getUserId()).thenReturn("UserId");
        when(adminEvent.getResourcePath()).thenReturn("ResourcePath/something1/something2/something3");
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        provider.onEvent(adminEvent, true);

        // Condition 5: ensure user details are appended
        when(userModel.getUsername()).thenReturn("username");
        when(userModel.getEmail()).thenReturn("some@email");
        provider = new MattermostEventListenerProvider(excludedEvents, includedAdminEvents, groups, serverUri, session);
        provider.onEvent(adminEvent, true);
    }

    @Test
    public void closeTest() {
        provider = new MattermostEventListenerProvider(null, null, groups, serverUri, session);
        assertNotNull(provider);
        provider.close();
    }
}
