package dod.p1.keycloak.events;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import org.jboss.logging.Logger;
import org.json.JSONObject;
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
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class JBossLoggingExtEventListenerProviderTest {

    @Mock
    private HashSet<EventType> excludedEvents;

    private final String serverUri = "serverURI";

    @Mock
    private KeycloakSession session;

    @Mock
    private UserModel userModel;

    @Mock
    private Logger logger;

    @Mock
    private Event event;

    @Mock
    private AdminEvent adminEvent;

    @Mock
    private KeycloakContext keycloakContext;

    @Mock
    private RealmModel realmModel;

    @Mock
    private UserProvider userProvider;

    @BeforeEach
    public void setUp() {
        // Stub the Keycloak session and context
        when(session.getContext()).thenReturn(keycloakContext);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.getUserById(any(), any())).thenReturn(userModel);

        // Stub UserModel
        when(userModel.getEmail()).thenReturn("some email");
        when(userModel.getUsername()).thenReturn("some username");

        // Create a mock for the expected KeycloakUriInfo type.
        KeycloakUriInfo dummyUriInfo = mock(KeycloakUriInfo.class);
        when(dummyUriInfo.getRequestUri()).thenReturn(URI.create(serverUri));
        when(keycloakContext.getUri()).thenReturn(dummyUriInfo);

        // Stub KeycloakContext to return a realm
        when(keycloakContext.getRealm()).thenReturn(realmModel);

        // Stub HttpHeaders for context if needed
        HttpHeaders headers = mock(HttpHeaders.class);
        when(keycloakContext.getRequestHeaders()).thenReturn(headers);
        when(headers.getCookies()).thenReturn(Collections.emptyMap());

        // Stub AdminEvent representation to include "clientId"
        when(adminEvent.getRepresentation()).thenReturn("{ \"name\": \"name\", \"path\": \"path\", \"clientId\": \"dummyClientId\" }");
    }

    @Test
    public void testJBossLoggingExtEventListenerProviderConstructor() {
        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(null, session, logger, null, null);
        assertNotNull(provider);
    }

    @Test
    public void testOnEventEvent() {
        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(null, session, logger, null, null);
        assertNotNull(provider);
        provider.onEvent(event);
    }

    @Test
    public void testOnEventEventConditions() {
        // Replace any null value with an empty string because Map.of disallows nulls.
        Map<String, String> details = Map.of(
                "username", "some username",
                "email", "someEmail",
                "other", ""
        );
        when(event.getDetails()).thenReturn(details);
        when(event.getError()).thenReturn("some error");
        when(event.getUserId()).thenReturn("some userId");
        when(event.getType()).thenReturn(EventType.USER_INFO_REQUEST);
        when(excludedEvents.contains(any())).thenReturn(true);

        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(excludedEvents, session, logger,
                        Logger.Level.DEBUG, Logger.Level.ERROR);

        provider.onEvent(event);

        // Now test with null error and details, and logger not trace enabled.
        when(event.getError()).thenReturn(null);
        when(event.getDetails()).thenReturn(null);
        when(logger.isTraceEnabled()).thenReturn(false);
        provider.onEvent(event);
    }

    @Test
    public void testOnEventAdminEvent() {
        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(null, session, logger, null, null);
        provider.onEvent(adminEvent, true);
    }

    @Test
    public void testOnEventAdminEventConditions() {
        // Setup AdminEvent stubs for different resource types
        AuthDetails authDetails = mock(AuthDetails.class);
        when(adminEvent.getAuthDetails()).thenReturn(authDetails);
        when(authDetails.getUserId()).thenReturn("userId");
        when(adminEvent.getResourcePath()).thenReturn("ResourcePath/something/something");
        when(logger.isEnabled(any())).thenReturn(true);
        when(logger.isTraceEnabled()).thenReturn(true);

        // Stub resource type to a dummy non-null value (e.g., CLIENT) to avoid NPE.
        when(adminEvent.getResourceType()).thenReturn(ResourceType.CLIENT);

        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(excludedEvents, session, logger,
                        Logger.Level.DEBUG, Logger.Level.ERROR);

        // Invoke multiple times to simulate various conditions.
        provider.onEvent(adminEvent, true);
        provider.onEvent(adminEvent, true);
        provider.onEvent(adminEvent, true);
        provider.onEvent(adminEvent, true);
        provider.onEvent(adminEvent, true);
        provider.onEvent(adminEvent, true);

        // Test with null representation.
        when(adminEvent.getRepresentation()).thenReturn(null);
        provider.onEvent(adminEvent, true);
    }

    @Test
    public void testClose() {
        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(null, session, logger, null, null);
        provider.close();
    }
}
