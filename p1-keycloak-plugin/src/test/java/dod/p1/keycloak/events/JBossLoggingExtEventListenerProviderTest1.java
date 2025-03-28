package dod.p1.keycloak.events;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
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
import org.keycloak.events.admin.OperationType;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class JBossLoggingExtEventListenerProviderTest1 {

    @Mock
    private HashSet<EventType> excludedEvents;

    private final String serverUri = "https://test-server.com";

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

    @Mock
    private HttpHeaders headers;

    @Mock
    private Map<String, Cookie> cookies;

    @BeforeEach
    public void setUp() {
        // Stub the Keycloak session and context
        when(session.getContext()).thenReturn(keycloakContext);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.getUserById(any(), any())).thenReturn(userModel);

        // Stub UserModel
        when(userModel.getEmail()).thenReturn("test.user@example.com");
        when(userModel.getUsername()).thenReturn("test.user");

        // Create a mock for the expected KeycloakUriInfo type.
        KeycloakUriInfo dummyUriInfo = mock(KeycloakUriInfo.class);
        when(dummyUriInfo.getRequestUri()).thenReturn(URI.create(serverUri));
        when(keycloakContext.getUri()).thenReturn(dummyUriInfo);

        // Stub KeycloakContext to return a realm
        when(keycloakContext.getRealm()).thenReturn(realmModel);

        // Stub HttpHeaders for context
        when(keycloakContext.getRequestHeaders()).thenReturn(headers);
        when(headers.getCookies()).thenReturn(cookies);

        // Stub logger
        when(logger.isEnabled(any(Logger.Level.class))).thenReturn(true);
    }

    @Test
    public void testOnEventWithDifferentEventTypes() {
        // Test with different event types
        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(excludedEvents, session, logger, Logger.Level.INFO, Logger.Level.ERROR);
        
        // Test with LOGIN event
        when(event.getType()).thenReturn(EventType.LOGIN);
        provider.onEvent(event);
        
        // Test with LOGOUT event
        when(event.getType()).thenReturn(EventType.LOGOUT);
        provider.onEvent(event);
        
        // Test with REGISTER event
        when(event.getType()).thenReturn(EventType.REGISTER);
        provider.onEvent(event);
        
        // Verify logger was called
        verify(logger, atLeast(3)).log(any(Logger.Level.class), anyString());
    }

    @Test
    public void testOnEventWithDetailedEventData() {
        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(excludedEvents, session, logger, Logger.Level.INFO, Logger.Level.ERROR);
        
        // Setup event with detailed data
        when(event.getType()).thenReturn(EventType.LOGIN);
        when(event.getRealmId()).thenReturn("test-realm");
        when(event.getClientId()).thenReturn("test-client");
        when(event.getUserId()).thenReturn("user-123");
        when(event.getIpAddress()).thenReturn("192.168.1.1");
        
        // Create event details with spaces in values
        Map<String, String> details = new HashMap<>();
        details.put("username", "test user");
        details.put("email", "test.user@example.com");
        details.put("auth_method", "password with 2FA");
        when(event.getDetails()).thenReturn(details);
        
        // Test with trace enabled
        when(logger.isTraceEnabled()).thenReturn(true);
        provider.onEvent(event);
        
        // Test with trace disabled
        when(logger.isTraceEnabled()).thenReturn(false);
        provider.onEvent(event);
        
        // Verify logger was called
        verify(logger, atLeast(2)).log(any(Logger.Level.class), anyString());
    }

    @Test
    public void testOnAdminEventWithDifferentResourceTypes() {
        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(excludedEvents, session, logger, Logger.Level.INFO, Logger.Level.ERROR);
        
        // Setup admin event
        AuthDetails authDetails = mock(AuthDetails.class);
        when(adminEvent.getAuthDetails()).thenReturn(authDetails);
        when(authDetails.getRealmId()).thenReturn("test-realm");
        when(authDetails.getClientId()).thenReturn("test-client");
        when(authDetails.getUserId()).thenReturn("user-123");
        when(authDetails.getIpAddress()).thenReturn("192.168.1.1");
        when(adminEvent.getResourcePath()).thenReturn("users/user-123");
        when(adminEvent.getOperationType()).thenReturn(OperationType.CREATE);
        
        // Test with GROUP resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP);
        when(adminEvent.getRepresentation()).thenReturn("{ \"name\": \"test-group\", \"path\": \"/test-group\" }");
        provider.onEvent(adminEvent, true);
        
        // Test with GROUP_MEMBERSHIP resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP_MEMBERSHIP);
        when(adminEvent.getResourcePath()).thenReturn("users/user-123/groups/group-456");
        when(adminEvent.getRepresentation()).thenReturn("{ \"name\": \"test-group\", \"path\": \"/test-group\" }");
        provider.onEvent(adminEvent, true);
        
        // Test with USER resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.USER);
        when(adminEvent.getRepresentation()).thenReturn("{ \"username\": \"test-user\", \"email\": \"test@example.com\" }");
        provider.onEvent(adminEvent, true);
        
        // Test with CLIENT resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.CLIENT);
        when(adminEvent.getRepresentation()).thenReturn("{ \"clientId\": \"test-client\", \"name\": \"Test Client\" }");
        provider.onEvent(adminEvent, true);
        
        // Test with PROTOCOL_MAPPER resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.PROTOCOL_MAPPER);
        when(adminEvent.getRepresentation()).thenReturn("{ \"name\": \"test-mapper\", \"protocol\": \"openid-connect\", \"protocolMapper\": \"oidc-usermodel-attribute-mapper\" }");
        provider.onEvent(adminEvent, true);
        
        // Test with CLIENT_ROLE resource type (nameOnlyResourceTypes)
        when(adminEvent.getResourceType()).thenReturn(ResourceType.CLIENT_ROLE);
        when(adminEvent.getRepresentation()).thenReturn("{ \"name\": \"test-role\" }");
        provider.onEvent(adminEvent, true);
        
        // Test with AUTH_FLOW resource type (allAttrResourceTypes)
        when(adminEvent.getResourceType()).thenReturn(ResourceType.AUTH_FLOW);
        when(adminEvent.getRepresentation()).thenReturn("{ \"alias\": \"browser\", \"description\": \"browser based authentication\" }");
        provider.onEvent(adminEvent, true);
        
        // Verify logger was called
        verify(logger, atLeast(7)).log(any(Logger.Level.class), anyString());
    }

    @Test
    public void testOnAdminEventWithError() {
        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(excludedEvents, session, logger, Logger.Level.INFO, Logger.Level.ERROR);
        
        // Setup admin event with error
        AuthDetails authDetails = mock(AuthDetails.class);
        when(adminEvent.getAuthDetails()).thenReturn(authDetails);
        when(adminEvent.getError()).thenReturn("validation_error");
        when(adminEvent.getResourceType()).thenReturn(ResourceType.USER);
        
        // Test with trace enabled
        when(logger.isTraceEnabled()).thenReturn(true);
        provider.onEvent(adminEvent, true);
        
        // Verify error level was used
        verify(logger).log(eq(Logger.Level.TRACE), anyString());
    }

    @Test
    public void testSetKeycloakContextWithMultipleCookies() {
        JBossLoggingExtEventListenerProvider provider =
                new JBossLoggingExtEventListenerProvider(excludedEvents, session, logger, Logger.Level.INFO, Logger.Level.ERROR);
        
        // Setup multiple cookies
        Map<String, Cookie> cookieMap = new HashMap<>();
        cookieMap.put("KEYCLOAK_SESSION", new Cookie("KEYCLOAK_SESSION", "value1"));
        cookieMap.put("KEYCLOAK_IDENTITY", new Cookie("KEYCLOAK_IDENTITY", "value2"));
        cookieMap.put("OTHER_COOKIE", new Cookie("OTHER_COOKIE", "value3"));
        when(headers.getCookies()).thenReturn(cookieMap);
        
        // Enable trace for setKeycloakContext to be called
        when(logger.isTraceEnabled()).thenReturn(true);
        
        // Test with event
        provider.onEvent(event);
        
        // Verify logger was called with trace level
        verify(logger).log(eq(Logger.Level.TRACE), anyString());
    }
}