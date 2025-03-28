package dod.p1.keycloak.events;

import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashSet;
import java.util.Set;

import static dod.p1.keycloak.events.EventListenerUtils.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Test class for {@link EventListenerUtils}.
 */
@RunWith(MockitoJUnitRunner.class)
public class EventListenerUtilsTest {

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
    private AdminEvent adminEvent;

    @Mock
    private AuthDetails authDetails;

    @Mock
    private Logger logger;

    private StringBuilder sb;

    @Before
    public void setUp() {
        sb = new StringBuilder();

        // Setup mocks
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(userProvider);
        
        when(adminEvent.getAuthDetails()).thenReturn(authDetails);
        when(authDetails.getRealmId()).thenReturn("test-realm");
        when(authDetails.getClientId()).thenReturn("test-client");
        when(authDetails.getUserId()).thenReturn("test-user-id");
        when(authDetails.getIpAddress()).thenReturn("127.0.0.1");
        when(adminEvent.getResourcePath()).thenReturn("users/test-user-id");
        when(adminEvent.getOperationType()).thenReturn(OperationType.CREATE);
        when(adminEvent.getResourceType()).thenReturn(ResourceType.USER);
    }

    @Test
    public void testInitializeAllAttrResourceTypes() {
        Set<ResourceType> types = initializeAllAttrResourceTypes();
        
        assertNotNull("Resource types should not be null", types);
        assertEquals("Should have 5 resource types", 5, types.size());
        assertTrue("Should contain AUTH_EXECUTION", types.contains(ResourceType.AUTH_EXECUTION));
        assertTrue("Should contain AUTH_FLOW", types.contains(ResourceType.AUTH_FLOW));
        assertTrue("Should contain AUTHENTICATOR_CONFIG", types.contains(ResourceType.AUTHENTICATOR_CONFIG));
        assertTrue("Should contain REQUIRED_ACTION", types.contains(ResourceType.REQUIRED_ACTION));
        assertTrue("Should contain REALM_ROLE_MAPPING", types.contains(ResourceType.REALM_ROLE_MAPPING));
    }

    @Test
    public void testInitializeNameOnlyResourceTypes() {
        Set<ResourceType> types = initializeNameOnlyResourceTypes();
        
        assertNotNull("Resource types should not be null", types);
        assertEquals("Should have 6 resource types", 6, types.size());
        assertTrue("Should contain CLIENT_ROLE", types.contains(ResourceType.CLIENT_ROLE));
        assertTrue("Should contain CLIENT_SCOPE_MAPPING", types.contains(ResourceType.CLIENT_SCOPE_MAPPING));
        assertTrue("Should contain CLIENT_ROLE_MAPPING", types.contains(ResourceType.CLIENT_ROLE_MAPPING));
        assertTrue("Should contain CLIENT_SCOPE", types.contains(ResourceType.CLIENT_SCOPE));
        assertTrue("Should contain REALM_ROLE", types.contains(ResourceType.REALM_ROLE));
        assertTrue("Should contain AUTHORIZATION_RESOURCE_SERVER", types.contains(ResourceType.AUTHORIZATION_RESOURCE_SERVER));
    }

    @Test
    public void testBuildBasicAdminEventInfo() {
        StringBuilder result = buildBasicAdminEventInfo(adminEvent);
        
        assertNotNull("Result should not be null", result);
        String resultStr = result.toString();
        assertTrue("Should contain operationType", resultStr.contains("operationType=CREATE"));
        assertTrue("Should contain resourceType", resultStr.contains("resourceType=USER"));
        assertTrue("Should contain realmId", resultStr.contains("realmId=test-realm"));
        assertTrue("Should contain clientId", resultStr.contains("clientId=test-client"));
        assertTrue("Should contain userId", resultStr.contains("userId=test-user-id"));
        assertTrue("Should contain ipAddress", resultStr.contains("ipAddress=127.0.0.1"));
        assertTrue("Should contain resourcePath", resultStr.contains("resourcePath=users/test-user-id"));
    }

    @Test
    public void testAppendErrorInfo() {
        when(adminEvent.getError()).thenReturn("test-error");
        
        appendErrorInfo(sb, adminEvent);
        
        assertEquals(", error=test-error", sb.toString());
    }

    @Test
    public void testAppendErrorInfoNoError() {
        when(adminEvent.getError()).thenReturn(null);
        
        appendErrorInfo(sb, adminEvent);
        
        assertEquals("", sb.toString());
    }

    @Test
    public void testAppendAdminUserInfo() {
        when(userProvider.getUserById(realm, "test-user-id")).thenReturn(user);
        when(user.getUsername()).thenReturn("test-username");
        when(user.getEmail()).thenReturn("test@example.com");
        
        appendAdminUserInfo(sb, adminEvent, session);
        
        String result = sb.toString();
        assertTrue("Should contain Admin_username", result.contains("Admin_username=test-username"));
        assertTrue("Should contain Admin_email", result.contains("Admin_email=test@example.com"));
    }

    @Test
    public void testAppendAdminUserInfoNoUser() {
        when(userProvider.getUserById(realm, "test-user-id")).thenReturn(null);
        
        appendAdminUserInfo(sb, adminEvent, session);
        
        assertEquals("", sb.toString());
    }

    @Test
    public void testAppendAdminUserInfoNoUserId() {
        when(authDetails.getUserId()).thenReturn(null);
        
        appendAdminUserInfo(sb, adminEvent, session);
        
        assertEquals("", sb.toString());
    }

    @Test
    public void testAppendGroupInfo() {
        JSONObject representation = new JSONObject();
        representation.put("name", "test-group");
        representation.put("path", "/test-path");
        
        appendGroupInfo(sb, representation);
        
        String result = sb.toString();
        assertTrue("Should contain name", result.contains("name=test-group"));
        assertTrue("Should contain path", result.contains("path=/test-path"));
    }

    @Test
    public void testAppendGroupInfoNoPath() {
        JSONObject representation = new JSONObject();
        representation.put("name", "test-group");
        
        appendGroupInfo(sb, representation);
        
        assertEquals(", name=test-group", sb.toString());
    }

    @Test
    public void testAppendUserRepresentationInfo() {
        JSONObject representation = new JSONObject();
        representation.put("username", "test-username");
        representation.put("email", "test@example.com");
        
        appendUserRepresentationInfo(sb, representation);
        
        String result = sb.toString();
        assertTrue("Should contain username", result.contains("username=test-username"));
        assertTrue("Should contain email", result.contains("email=test@example.com"));
    }

    @Test
    public void testAppendClientInfo() {
        JSONObject representation = new JSONObject();
        representation.put("clientId", "test-client-id");
        representation.put("name", "test-client-name");
        
        appendClientInfo(sb, representation);
        
        String result = sb.toString();
        assertTrue("Should contain clientId", result.contains("clientId=test-client-id"));
        assertTrue("Should contain name", result.contains("name=test-client-name"));
    }

    @Test
    public void testAppendClientInfoNoName() {
        JSONObject representation = new JSONObject();
        representation.put("clientId", "test-client-id");
        
        appendClientInfo(sb, representation);
        
        assertEquals(", clientId=test-client-id", sb.toString());
    }

    @Test
    public void testAppendProtocolMapperInfo() {
        JSONObject representation = new JSONObject();
        representation.put("name", "test-mapper");
        representation.put("protocol", "openid-connect");
        representation.put("protocolMapper", "oidc-usermodel-attribute-mapper");
        
        appendProtocolMapperInfo(sb, representation);
        
        String result = sb.toString();
        assertTrue("Should contain name", result.contains("name=test-mapper"));
        assertTrue("Should contain protocol", result.contains("protocol=openid-connect"));
        assertTrue("Should contain protocolMapper", result.contains("protocolMapper=oidc-usermodel-attribute-mapper"));
    }

    @Test
    public void testLogEvent() {
        sb.append("test-message");
        Logger.Level level = Logger.Level.INFO;
        
        logEvent(logger, sb, level);
        
        verify(logger).log(level, "test-message");
    }

    @Test
    public void testLogEventWithTraceEnabled() {
        sb.append("test-message");
        Logger.Level level = Logger.Level.INFO;
        when(logger.isTraceEnabled()).thenReturn(true);
        
        logEvent(logger, sb, level);
        
        verify(logger).log(Logger.Level.TRACE, "test-message");
    }

    @Test
    public void testGetRepresentation() {
        String jsonStr = "{\"name\":\"test-name\",\"value\":123}";
        when(adminEvent.getRepresentation()).thenReturn(jsonStr);
        
        JSONObject result = getRepresentation(adminEvent);
        
        assertNotNull("Result should not be null", result);
        assertEquals("test-name", result.getString("name"));
        assertEquals(123, result.getInt("value"));
    }

    @Test
    public void testAppendRepresentationInfo() {
        // Setup for USER resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.USER);
        String userJson = "{\"username\":\"test-user\",\"email\":\"test@example.com\"}";
        when(adminEvent.getRepresentation()).thenReturn(userJson);
        
        Set<ResourceType> allAttrTypes = initializeAllAttrResourceTypes();
        Set<ResourceType> nameOnlyTypes = initializeNameOnlyResourceTypes();
        
        String result = appendRepresentationInfo(sb, adminEvent, session, allAttrTypes, nameOnlyTypes);
        
        assertEquals("", result); // No path returned for USER type
        assertTrue(sb.toString().contains("username=test-user"));
        assertTrue(sb.toString().contains("email=test@example.com"));
        
        // Reset and test for GROUP resource type
        sb = new StringBuilder();
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP);
        String groupJson = "{\"name\":\"test-group\",\"path\":\"/test-path\"}";
        when(adminEvent.getRepresentation()).thenReturn(groupJson);
        
        result = appendRepresentationInfo(sb, adminEvent, session, allAttrTypes, nameOnlyTypes);
        
        assertEquals("", result); // No path returned for GROUP type
        assertTrue(sb.toString().contains("name=test-group"));
        assertTrue(sb.toString().contains("path=/test-path"));
    }

    @Test
    public void testAppendGroupMembershipInfo() {
        when(adminEvent.getResourcePath()).thenReturn("users/user-id/groups/group-id");
        JSONObject representation = new JSONObject();
        representation.put("name", "test-group");
        representation.put("path", "/test-path");
        
        when(userProvider.getUserById(eq(realm), eq("user-id"))).thenReturn(user);
        when(user.getUsername()).thenReturn("test-username");
        
        String result = appendGroupMembershipInfo(sb, representation, adminEvent, session);
        
        assertEquals("/test-path", result);
        assertTrue(sb.toString().contains("name=test-group"));
        assertTrue(sb.toString().contains("path=/test-path"));
        assertTrue(sb.toString().contains("username=test-username"));
    }
}