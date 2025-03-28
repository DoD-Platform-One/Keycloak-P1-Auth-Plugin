package org.keycloak.forms.account.freemarker.model;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Additional tests for the {@link AuthorizationBean} class focusing on ResourceBean.
 */
public class AuthorizationBeanResourceTest {

    private KeycloakSession session;
    private UserModel user;
    private UriInfo uriInfo;
    private AuthorizationProvider authorizationProvider;
    private StoreFactory storeFactory;
    private ResourceStore resourceStore;
    private PermissionTicketStore permissionTicketStore;
    private PolicyStore policyStore;
    private RealmModel realm;
    private UserProvider userProvider;
    private AuthorizationBean authorizationBean;
    private Resource resource;
    private ResourceServer resourceServer;
    private ClientModel clientModel;

    @BeforeEach
    public void setUp() {
        // Setup mocks
        session = mock(KeycloakSession.class);
        user = mock(UserModel.class);
        uriInfo = mock(UriInfo.class);
        authorizationProvider = mock(AuthorizationProvider.class);
        storeFactory = mock(StoreFactory.class);
        resourceStore = mock(ResourceStore.class);
        permissionTicketStore = mock(PermissionTicketStore.class);
        policyStore = mock(PolicyStore.class);
        realm = mock(RealmModel.class);
        userProvider = mock(UserProvider.class);
        resource = mock(Resource.class);
        resourceServer = mock(ResourceServer.class);
        clientModel = mock(ClientModel.class);
        
        // Setup common values
        when(user.getId()).thenReturn("user-id");
        when(user.getUsername()).thenReturn("test-user");
        when(session.getProvider(AuthorizationProvider.class)).thenReturn(authorizationProvider);
        when(authorizationProvider.getStoreFactory()).thenReturn(storeFactory);
        when(storeFactory.getResourceStore()).thenReturn(resourceStore);
        when(storeFactory.getPermissionTicketStore()).thenReturn(permissionTicketStore);
        when(storeFactory.getPolicyStore()).thenReturn(policyStore);
        when(authorizationProvider.getKeycloakSession()).thenReturn(session);
        when(authorizationProvider.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(userProvider);
        
        // Setup empty path parameters
        MultivaluedMap<String, String> pathParams = new MultivaluedHashMap<>();
        when(uriInfo.getPathParameters()).thenReturn(pathParams);
        
        // Setup resource
        when(resource.getId()).thenReturn("resource-id");
        when(resource.getName()).thenReturn("Resource Name");
        when(resource.getDisplayName()).thenReturn("Resource Display Name");
        when(resource.getIconUri()).thenReturn("resource-icon-uri");
        when(resource.getOwner()).thenReturn("user-id");
        when(resource.isOwnerManagedAccess()).thenReturn(true);
        when(resource.getResourceServer()).thenReturn(resourceServer);
        
        // Setup resource server
        when(resourceServer.getClientId()).thenReturn("client-id");
        when(realm.getClientById("client-id")).thenReturn(clientModel);
        
        // Setup client model
        when(clientModel.getClientId()).thenReturn("client-id");
        
        // Setup user provider
        when(userProvider.getUserById(eq(realm), eq("user-id"))).thenReturn(user);
        
        // Create the bean
        authorizationBean = new AuthorizationBean(session, user, uriInfo);
    }

    @Test
    public void testResourceBean_WithUserOwner() {
        // Setup
        when(user.getEmail()).thenReturn("user@example.com");
        
        // Create ResourceBean
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Verify
        assertNotNull(resourceBean);
        assertEquals("resource-id", resourceBean.getId());
        assertEquals("Resource Name", resourceBean.getName());
        assertEquals("Resource Display Name", resourceBean.getDisplayName());
        assertEquals("resource-icon-uri", resourceBean.getIconUri());
        assertEquals("user@example.com", resourceBean.getOwnerName());
        assertEquals(user, resourceBean.getUserOwner());
        assertNull(resourceBean.getClientOwner());
    }

    @Test
    public void testResourceBean_WithUserOwnerNoEmail() {
        // Setup
        when(user.getEmail()).thenReturn(null);
        
        // Create ResourceBean
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Verify
        assertEquals("test-user", resourceBean.getOwnerName());
    }

    @Test
    public void testResourceBean_WithClientOwner() {
        // Setup
        when(resource.getOwner()).thenReturn("client-owner-id");
        when(userProvider.getUserById(eq(realm), eq("client-owner-id"))).thenReturn(null);
        
        ClientModel clientOwner = mock(ClientModel.class);
        when(clientOwner.getClientId()).thenReturn("client-owner");
        when(realm.getClientById("client-owner-id")).thenReturn(clientOwner);
        
        // Create ResourceBean
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Verify
        assertEquals("client-owner", resourceBean.getOwnerName());
        assertNull(resourceBean.getUserOwner());
        assertEquals(clientOwner, resourceBean.getClientOwner());
    }

    @Test
    public void testResourceBean_GetScopes() {
        // Setup
        List<Scope> scopes = new ArrayList<>();
        Scope scope1 = mock(Scope.class);
        when(scope1.getId()).thenReturn("scope-1");
        when(scope1.getName()).thenReturn("Scope 1");
        scopes.add(scope1);
        
        when(resource.getScopes()).thenReturn(scopes);
        
        // Create ResourceBean
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Verify
        List<ScopeRepresentation> scopeRepresentations = resourceBean.getScopes();
        assertNotNull(scopeRepresentations);
        assertFalse(scopeRepresentations.isEmpty());
    }

    @Test
    public void testResourceBean_GetShares_WithPermissions() {
        // Setup
        List<PermissionTicket> tickets = new ArrayList<>();
        PermissionTicket ticket = mock(PermissionTicket.class);
        when(ticket.getResource()).thenReturn(resource);
        when(ticket.getRequester()).thenReturn("requester-id");
        when(ticket.isGranted()).thenReturn(true);
        tickets.add(ticket);
        
        UserModel requester = mock(UserModel.class);
        when(requester.getId()).thenReturn("requester-id");
        when(userProvider.getUserById(eq(realm), eq("requester-id"))).thenReturn(requester);
        
        when(permissionTicketStore.find(isNull(), any(Map.class), isNull(), isNull()))
            .thenReturn(tickets);
        
        // Create ResourceBean
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Verify
        Collection<AuthorizationBean.RequesterBean> shares = resourceBean.getShares();
        assertNotNull(shares);
        assertFalse(shares.isEmpty());
        assertEquals(1, shares.size());
    }

    @Test
    public void testResourceBean_GetPolicies_WithPolicies() {
        // Setup
        List<Policy> policies = new ArrayList<>();
        Policy policy = mock(Policy.class);
        when(policy.getId()).thenReturn("policy-id");
        when(policy.getDescription()).thenReturn("Policy Description");
        when(policy.getScopes()).thenReturn(Collections.emptySet());
        when(policy.getAssociatedPolicies()).thenReturn(Collections.emptySet());
        policies.add(policy);
        
        when(policyStore.find(any(ResourceServer.class), any(Map.class), isNull(), isNull()))
            .thenReturn(policies);
        
        when(permissionTicketStore.find(any(ResourceServer.class), any(Map.class), eq(-1), eq(1)))
            .thenReturn(Collections.emptyList());
        
        // Create ResourceBean
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Verify
        Collection<AuthorizationBean.ManagedPermissionBean> managedPermissions = resourceBean.getPolicies();
        assertNotNull(managedPermissions);
        assertFalse(managedPermissions.isEmpty());
        assertEquals(1, managedPermissions.size());
        assertEquals("policy-id", managedPermissions.iterator().next().getId());
    }

    @Test
    public void testResourceBean_GetPolicies_WithTickets() {
        // Setup
        List<Policy> policies = new ArrayList<>();
        Policy policy = mock(Policy.class);
        when(policy.getId()).thenReturn("policy-id");
        policies.add(policy);
        
        when(policyStore.find(any(ResourceServer.class), any(Map.class), isNull(), isNull()))
            .thenReturn(policies);
        
        List<PermissionTicket> tickets = new ArrayList<>();
        PermissionTicket ticket = mock(PermissionTicket.class);
        tickets.add(ticket);
        
        when(permissionTicketStore.find(any(ResourceServer.class), any(Map.class), eq(-1), eq(1)))
            .thenReturn(tickets);
        
        // Create ResourceBean
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Verify
        Collection<AuthorizationBean.ManagedPermissionBean> managedPermissions = resourceBean.getPolicies();
        assertNotNull(managedPermissions);
        assertTrue(managedPermissions.isEmpty());
    }

    @Test
    public void testResourceBean_GetPermissions() {
        // Setup
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Verify
        Collection<AuthorizationBean.RequesterBean> permissions = resourceBean.getPermissions();
        assertNotNull(permissions);
        assertTrue(permissions.isEmpty());
        
        // Add a permission
        PermissionTicket ticket = mock(PermissionTicket.class);
        when(ticket.getRequester()).thenReturn("requester-id");
        when(ticket.isGranted()).thenReturn(true);
        
        UserModel requester = mock(UserModel.class);
        when(requester.getId()).thenReturn("requester-id");
        when(userProvider.getUserById(eq(realm), eq("requester-id"))).thenReturn(requester);
        
        // Use reflection to access private method
        try {
            java.lang.reflect.Method addPermissionMethod = AuthorizationBean.ResourceBean.class.getDeclaredMethod("addPermission", PermissionTicket.class);
            addPermissionMethod.setAccessible(true);
            addPermissionMethod.invoke(resourceBean, ticket);
            
            // Verify
            permissions = resourceBean.getPermissions();
            assertNotNull(permissions);
            assertFalse(permissions.isEmpty());
            assertEquals(1, permissions.size());
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke addPermission method", e);
        }
    }
}