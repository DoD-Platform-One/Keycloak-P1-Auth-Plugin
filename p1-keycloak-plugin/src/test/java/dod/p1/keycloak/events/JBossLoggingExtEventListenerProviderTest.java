package dod.p1.keycloak.events;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import org.jboss.logging.Logger;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.*;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URI;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({
})
public class JBossLoggingExtEventListenerProviderTest {

    @Mock
    private HashSet<EventType> excludedEvents;
    @Mock private HashSet<ResourceType> includedAdminEvents;
    private final String[] groups = {"group1", "group2", "group3"};
    private final String serverUri = "serverURI";
    @Mock private KeycloakSession session;
    @Mock private UserModel userModel;
    @Mock private Logger logger;
    @Mock private Event event;
    @Mock private AdminEvent adminEvent;
    @Mock private KeycloakContext keycloakContext;
    @Mock private RealmModel realmModel;
    @Mock private UserProvider userProvider;

    @Before
    public void setUp() {
        // keycloakSession
        when(session.getContext()).thenReturn(keycloakContext);
        when(session.users()).thenReturn(userProvider);
        when(session.users().getUserById(any(), any())).thenReturn(userModel);

        // userModel
        when(userModel.getEmail()).thenReturn("some email");
        when(userModel.getUsername()).thenReturn("some username");

        // keycloakContext
        when(keycloakContext.getRealm()).thenReturn(realmModel);

        // adminEvent
        when(adminEvent.getRepresentation()).thenReturn("{ " +
                "Representation: representation, " +
                "path: path, " +
                "name: name, " +
                "username: username, " +
                "email: email, " +
                "protocol: protocol, " +
                "protocolMapper: protocolMapper, " +
                "clientId: clientId, " +
                "}");

    }

    @Test
    public void JBossLoggingExtEventListenerProviderConstructor(){
        // Constructor
        JBossLoggingExtEventListenerProvider provider = new JBossLoggingExtEventListenerProvider(null, session, logger, null, null);

        // check the constructor
        assertNotNull(provider);
    }

    @Test
    public void onEventEventTest(){
        // Constructor with nulls
        JBossLoggingExtEventListenerProvider provider = new JBossLoggingExtEventListenerProvider(null, session, logger, null, null);

        // check the constructor
        assertNotNull(provider);

        // onEvent (1)
        provider.onEvent(event);
    }

    @Test
    public void onEventEventTestsConditions(){
        // Var
        Set<Map.Entry<String, Cookie>> cookieSet = new HashSet<>();
        Set<Map.Entry<String, String>> mockedSet = new HashSet<>();

        // Mocks
        KeycloakUriInfo keycloakUriInfo = mock(KeycloakUriInfo.class);
        HttpHeaders headers = mock(HttpHeaders.class);

        // Entry Mock
        Map<String, String> mockedMap = mock(Map.class);
        Map.Entry<String, String> entry1 = mock(Map.Entry.class);
        Map.Entry<String, String> entry2 = mock(Map.Entry.class);
        Map.Entry<String, String> entry3 = mock(Map.Entry.class);

        when(entry1.getKey()).thenReturn("username");
        when(entry1.getValue()).thenReturn("some username");
        when(entry2.getKey()).thenReturn("email");
        when(entry2.getValue()).thenReturn("someEmail");
        when(entry3.getKey()).thenReturn("something null");
        when(entry3.getValue()).thenReturn(null);
        mockedSet.add(entry1);
        mockedSet.add(entry2);
        mockedSet.add(entry3);

        // Cookies Mock
        Map<String, Cookie> cookieMap = mock(Map.class);
        Map.Entry<String, Cookie> cookie1 = mock(Map.Entry.class);
        Map.Entry<String, Cookie> cookie2 = mock(Map.Entry.class);

        when(cookie1.getKey()).thenReturn("cookie1");
        when(cookie1.getValue()).thenReturn(mock(Cookie.class));
        when(cookie2.getKey()).thenReturn("cookie2");
        when(cookie2.getValue()).thenReturn(mock(Cookie.class));
        cookieSet.add(cookie1);
        cookieSet.add(cookie2);

        // keycloakUriInfo
        when(keycloakUriInfo.getRequestUri()).thenReturn(mock(URI.class));

        // HttpHeaders
        when(headers.getCookies()).thenReturn(cookieMap);
        when(headers.getCookies().entrySet()).thenReturn(cookieSet);

        // logger
        when(logger.isEnabled(any())).thenReturn(true);
        when(logger.isTraceEnabled()).thenReturn(true);

        // event
        when(event.getError()).thenReturn("some error");
        when(event.getUserId()).thenReturn("some userId");
        when(event.getType()).thenReturn(EventType.USER_INFO_REQUEST);
        when(event.getDetails()).thenReturn(mockedMap);
        when(event.getDetails().entrySet()).thenReturn(mockedSet);

        // excludedEvents
        when(excludedEvents.contains(any())).thenReturn(true);

        // keycloakContext
        when(keycloakContext.getUri()).thenReturn(keycloakUriInfo);
        when(keycloakContext.getRequestHeaders()).thenReturn(headers);

        // Constructor
        JBossLoggingExtEventListenerProvider provider = new JBossLoggingExtEventListenerProvider(excludedEvents, session, logger, Logger.Level.DEBUG, Logger.Level.ERROR);

        // check the constructor
        assertNotNull(provider);

        // CONDITION 1 onEvent (1) condition true
        provider.onEvent(event);

        // CONDITION 2 onEvent (1)
        when(event.getType()).thenReturn(null);
        when(excludedEvents.contains(any())).thenReturn(false);
        provider.onEvent(event);

        // CONDITION 3 onEvent (1)
        when(event.getDetails().entrySet()).thenReturn(new HashSet<>());
        provider.onEvent(event);

        // CONDITION 4 onEvent (1)
        when(userModel.getEmail()).thenReturn(null);
        when(userModel.getUsername()).thenReturn(null);
        provider.onEvent(event);

        // CONDITION 5 onEvent (1) condition null
        when(excludedEvents.contains(any())).thenReturn(true);
        when(event.getUserId()).thenReturn(null);
        provider.onEvent(event);

        // CONDITION 6
        when(event.getError()).thenReturn(null);
        when(event.getDetails()).thenReturn(null);
        when(logger.isTraceEnabled()).thenReturn(false);
        provider.onEvent(event);

    }

    @Test
    public void onEventAdminEventTest(){
        // Constructor
        JBossLoggingExtEventListenerProvider provider = new JBossLoggingExtEventListenerProvider(null, session, logger, null, null);

        // check the constructor
        assertNotNull(provider);

        // onEvent (2)
        provider.onEvent(adminEvent, true);
    }

    @Test
    public void onEventAdminEventTestConditions() {
        // Mocks
        AuthDetails authDetails = mock(AuthDetails.class);

        // logger
        when(logger.isEnabled(any())).thenReturn(true);
        when(logger.isTraceEnabled()).thenReturn(true);

        // adminEvent
        when(adminEvent.getError()).thenReturn("another error");
        when(adminEvent.getAuthDetails()).thenReturn(authDetails);
        when(adminEvent.getAuthDetails().getUserId()).thenReturn("userId");
        when(adminEvent.getResourcePath()).thenReturn("ResourcePath/something1/something2/something3");

        // Constructor
        JBossLoggingExtEventListenerProvider provider = new JBossLoggingExtEventListenerProvider(excludedEvents, session, logger, Logger.Level.DEBUG, Logger.Level.ERROR);

        // check the constructor
        assertNotNull(provider);

        // onEvent (2) condition GROUP
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP);
        provider.onEvent(adminEvent, true);

        // onEvent (2) condition GROUP_MEMBERSHIP
        when(userModel.getEmail()).thenReturn(null);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP_MEMBERSHIP);
        provider.onEvent(adminEvent, true);

        // onEvent (2) condition USER
        when(userModel.getUsername()).thenReturn(null);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.USER);
        provider.onEvent(adminEvent, true);

        // onEvent (2) condition CLIENT
        when(adminEvent.getAuthDetails().getUserId()).thenReturn(null);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.CLIENT);
        provider.onEvent(adminEvent, true);

        // onEvent (2) condition PROTOCOL_MAPPER
        when(adminEvent.getError()).thenReturn(null);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.PROTOCOL_MAPPER);
        provider.onEvent(adminEvent, true);

        // onEvent (2) condition AUTH_EXECUTION
        when(adminEvent.getResourceType()).thenReturn(ResourceType.AUTH_EXECUTION);
        provider.onEvent(adminEvent, true);

        // onEvent (2) condition CLIENT_ROLE
        when(logger.isTraceEnabled()).thenReturn(false);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.CLIENT_ROLE);
        provider.onEvent(adminEvent, true);


        // onEvent (2) condition 2 GROUP (no path)
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP);
        when(adminEvent.getRepresentation()).thenReturn("{ " +
                "Representation: representation, " +
//                "path: path, " +
                "name: name," +
                "username: username, " +
                "email: email, " +
                "protocol: protocol, " +
                "protocolMapper: protocolMapper, " +
                "clientId: clientId, " +
                "}");
        provider.onEvent(adminEvent, true);


        // onEvent (2) condition 2 CLIENT (no name)
        when(adminEvent.getResourceType()).thenReturn(ResourceType.CLIENT);
        when(adminEvent.getRepresentation()).thenReturn("{ " +
                "Representation: representation, " +
                "path: path, " +
//                "name: name," +
                "username: username, " +
                "email: email, " +
                "protocol: protocol, " +
                "protocolMapper: protocolMapper, " +
                "clientId: clientId, " +
                "}");
        provider.onEvent(adminEvent, true);

        // onEvent (2) Representation null
        when(adminEvent.getRepresentation()).thenReturn(null);
        provider.onEvent(adminEvent, true);
    }

    @Test
    public void closeTest(){
        // Constructor
        JBossLoggingExtEventListenerProvider provider = new JBossLoggingExtEventListenerProvider(null, session, logger, null, null);

        // check the constructor
        assertNotNull(provider);

        // close
        provider.close();
    }
}