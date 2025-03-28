package dod.p1.keycloak.events;

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
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class MattermostEventListenerProviderTest2 {

    @Mock
    private HashSet<EventType> excludedEvents;

    @Mock
    private HashSet<ResourceType> includedAdminEvents;

    private final String[] groups = {"/group1", "/group2", "/group3"};
    private final String serverUri = "https://mattermost.example.com/hooks/webhook-token";

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakContext keycloakContext;

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

    @Mock
    private AuthDetails authDetails;

    @BeforeEach
    public void setUp() {
        // Stub session context and user provider to prevent NPEs
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getRealm()).thenReturn(realmModel);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.getUserById(any(RealmModel.class), anyString())).thenReturn(userModel);
        
        // Stub user model
        when(userModel.getUsername()).thenReturn("test-user");
        when(userModel.getEmail()).thenReturn("test@example.com");
        
        // Stub admin event
        when(adminEvent.getAuthDetails()).thenReturn(authDetails);
        when(authDetails.getUserId()).thenReturn("user-123");
    }

    @Test
    public void testConstructorWithAllParameters() {
        // Create provider with all parameters
        MattermostEventListenerProvider provider = new MattermostEventListenerProvider(
                excludedEvents, includedAdminEvents, groups, serverUri, session);
        
        // Verify provider is not null
        assertNotNull(provider);
    }

    @Test
    public void testOnEventWithDifferentEventTypes() {
        // Create provider
        MattermostEventListenerProvider provider = new MattermostEventListenerProvider(
                excludedEvents, includedAdminEvents, groups, serverUri, session);
        
        // Test with LOGIN event
        when(event.getType()).thenReturn(EventType.LOGIN);
        provider.onEvent(event);
        
        // Test with LOGOUT event
        when(event.getType()).thenReturn(EventType.LOGOUT);
        provider.onEvent(event);
        
        // Test with REGISTER event
        when(event.getType()).thenReturn(EventType.REGISTER);
        provider.onEvent(event);
    }

    @Test
    public void testOnAdminEventWithNonIncludedResourceType() {
        // Create provider
        MattermostEventListenerProvider provider = new MattermostEventListenerProvider(
                excludedEvents, includedAdminEvents, groups, serverUri, session);
        
        // Setup admin event with non-included resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.USER);
        when(includedAdminEvents.contains(ResourceType.USER)).thenReturn(false);
        
        // Call onEvent with admin event
        provider.onEvent(adminEvent, true);
    }

    @Test
    public void testOnAdminEventWithIncludedResourceType() {
        // Create provider
        MattermostEventListenerProvider provider = new MattermostEventListenerProvider(
                excludedEvents, includedAdminEvents, groups, serverUri, session);
        
        // Setup admin event with included resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP);
        when(includedAdminEvents.contains(ResourceType.GROUP)).thenReturn(true);
        when(adminEvent.getRepresentation()).thenReturn("{ \"name\": \"test-group\", \"path\": \"/test-group\" }");
        
        // Call onEvent with admin event
        provider.onEvent(adminEvent, true);
    }

    @Test
    public void testOnAdminEventWithDifferentResourceTypes() {
        // Create provider
        MattermostEventListenerProvider provider = new MattermostEventListenerProvider(
                excludedEvents, includedAdminEvents, groups, serverUri, session);
        
        // Setup admin event with included resource type
        when(includedAdminEvents.contains(any())).thenReturn(true);
        
        // Test with GROUP resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP);
        when(adminEvent.getRepresentation()).thenReturn("{ \"name\": \"test-group\", \"path\": \"/test-group\" }");
        provider.onEvent(adminEvent, true);
        
        // Test with GROUP_MEMBERSHIP resource type
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP_MEMBERSHIP);
        when(adminEvent.getResourcePath()).thenReturn("users/user-123/groups/group-456");
        when(adminEvent.getRepresentation()).thenReturn("{ \"name\": \"test-group\", \"path\": \"/group1\" }");
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
    }

    @Test
    public void testOnAdminEventWithError() {
        // Create provider
        MattermostEventListenerProvider provider = new MattermostEventListenerProvider(
                excludedEvents, includedAdminEvents, groups, serverUri, session);
        
        // Setup admin event with error
        when(adminEvent.getResourceType()).thenReturn(ResourceType.USER);
        when(includedAdminEvents.contains(ResourceType.USER)).thenReturn(true);
        when(adminEvent.getError()).thenReturn("validation_error");
        when(adminEvent.getRepresentation()).thenReturn("{ \"username\": \"test-user\", \"email\": \"test@example.com\" }");
        
        // Call onEvent with admin event
        provider.onEvent(adminEvent, true);
    }

    @Test
    public void testOnAdminEventWithGroupMembershipNotInGroups() {
        // Create provider with specific groups
        String[] specificGroups = {"/group1", "/group2"};
        MattermostEventListenerProvider provider = new MattermostEventListenerProvider(
                excludedEvents, includedAdminEvents, specificGroups, serverUri, session);
        
        // Setup admin event with GROUP_MEMBERSHIP resource type but path not in groups
        when(adminEvent.getResourceType()).thenReturn(ResourceType.GROUP_MEMBERSHIP);
        when(includedAdminEvents.contains(ResourceType.GROUP_MEMBERSHIP)).thenReturn(true);
        when(adminEvent.getResourcePath()).thenReturn("users/user-123/groups/group-456");
        when(adminEvent.getRepresentation()).thenReturn("{ \"name\": \"test-group\", \"path\": \"/not-in-groups\" }");
        
        // Call onEvent with admin event
        provider.onEvent(adminEvent, true);
    }

    @Test
    public void testClose() {
        // Create provider
        MattermostEventListenerProvider provider = new MattermostEventListenerProvider(
                excludedEvents, includedAdminEvents, groups, serverUri, session);
        
        // Call close
        provider.close();
        
        // No assertions needed as close is empty, but we're ensuring code coverage
    }
}