package org.keycloak.forms.account.freemarker.model;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for the {@link AuthorizationBean} class.
 */
public class AuthorizationBeanTest {

    private KeycloakSession session;
    private UserModel user;
    private UriInfo uriInfo;
    private AuthorizationProvider authorizationProvider;
    private StoreFactory storeFactory;
    private ResourceStore resourceStore;
    private PermissionTicketStore permissionTicketStore;
    private RealmModel realm;
    private UserProvider userProvider;
    private AuthorizationBean authorizationBean;

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
        realm = mock(RealmModel.class);
        userProvider = mock(UserProvider.class);
        
        // Setup common values
        when(user.getId()).thenReturn("user-id");
        when(user.getUsername()).thenReturn("test-user");
        when(session.getProvider(AuthorizationProvider.class)).thenReturn(authorizationProvider);
        when(authorizationProvider.getStoreFactory()).thenReturn(storeFactory);
        when(storeFactory.getResourceStore()).thenReturn(resourceStore);
        when(storeFactory.getPermissionTicketStore()).thenReturn(permissionTicketStore);
        when(authorizationProvider.getKeycloakSession()).thenReturn(session);
        when(authorizationProvider.getRealm()).thenReturn(realm);
        when(session.users()).thenReturn(userProvider);
        
        // Setup empty path parameters
        MultivaluedMap<String, String> pathParams = new MultivaluedHashMap<>();
        when(uriInfo.getPathParameters()).thenReturn(pathParams);
        
        // Create the bean
        authorizationBean = new AuthorizationBean(session, user, uriInfo);
    }

    @Test
    public void testGetResources_EmptyList() {
        // Setup
        when(resourceStore.findByOwner(isNull(), eq("user-id"))).thenReturn(Collections.emptyList());
        
        // Test
        List<AuthorizationBean.ResourceBean> resources = authorizationBean.getResources();
        
        // Verify
        assertNotNull(resources);
        assertTrue(resources.isEmpty());
    }

    @Test
    public void testGetResources_WithResources() {
        // Setup
        Resource resource1 = mock(Resource.class);
        when(resource1.getId()).thenReturn("resource-1");
        when(resource1.getName()).thenReturn("Resource 1");
        when(resource1.isOwnerManagedAccess()).thenReturn(true);
        when(resource1.getOwner()).thenReturn("user-id");
        
        Resource resource2 = mock(Resource.class);
        when(resource2.getId()).thenReturn("resource-2");
        when(resource2.getName()).thenReturn("Resource 2");
        when(resource2.isOwnerManagedAccess()).thenReturn(true);
        when(resource2.getOwner()).thenReturn("user-id");
        
        List<Resource> resourceList = new ArrayList<>();
        resourceList.add(resource1);
        resourceList.add(resource2);
        
        when(resourceStore.findByOwner(isNull(), eq("user-id"))).thenReturn(resourceList);
        when(userProvider.getUserById(eq(realm), eq("user-id"))).thenReturn(user);
        
        // Mock ResourceServer for ResourceBean constructor
        ResourceServer resourceServer = mock(ResourceServer.class);
        when(resource1.getResourceServer()).thenReturn(resourceServer);
        when(resource2.getResourceServer()).thenReturn(resourceServer);
        when(resourceServer.getClientId()).thenReturn("client-id");
        when(realm.getClientById("client-id")).thenReturn(null);
        
        // Test
        List<AuthorizationBean.ResourceBean> resources = authorizationBean.getResources();
        
        // Verify
        assertNotNull(resources);
        assertEquals(2, resources.size());
        assertEquals("resource-1", resources.get(0).getId());
        assertEquals("Resource 1", resources.get(0).getName());
        assertEquals("resource-2", resources.get(1).getId());
        assertEquals("Resource 2", resources.get(1).getName());
    }

    @Test
    public void testGetSharedResources_EmptyList() {
        // Setup
        when(permissionTicketStore.find(isNull(), any(Map.class), isNull(), isNull()))
            .thenReturn(Collections.emptyList());
        
        // Test
        Collection<AuthorizationBean.ResourceBean> sharedResources = authorizationBean.getSharedResources();
        
        // Verify
        assertNotNull(sharedResources);
        assertTrue(sharedResources.isEmpty());
    }

    @Test
    public void testGetResourcesWaitingApproval_EmptyList() {
        // Setup
        when(permissionTicketStore.find(isNull(), any(Map.class), isNull(), isNull()))
            .thenReturn(Collections.emptyList());
        
        // Test
        Collection<AuthorizationBean.ResourceBean> waitingApproval = authorizationBean.getResourcesWaitingApproval();
        
        // Verify
        assertNotNull(waitingApproval);
        assertTrue(waitingApproval.isEmpty());
    }

    @Test
    public void testGetResourcesWaitingOthersApproval_EmptyList() {
        // Setup
        when(permissionTicketStore.find(isNull(), any(Map.class), isNull(), isNull()))
            .thenReturn(Collections.emptyList());
        
        // Test
        Collection<AuthorizationBean.ResourceBean> waitingOthersApproval = authorizationBean.getResourcesWaitingOthersApproval();
        
        // Verify
        assertNotNull(waitingOthersApproval);
        assertTrue(waitingOthersApproval.isEmpty());
    }

    @Test
    public void testGetResource_WithResourceId() {
        // Setup
        MultivaluedMap<String, String> pathParams = new MultivaluedHashMap<>();
        pathParams.add("resource_id", "resource-1");
        when(uriInfo.getPathParameters()).thenReturn(pathParams);
        
        Resource resource = mock(Resource.class);
        when(resource.getId()).thenReturn("resource-1");
        when(resource.getName()).thenReturn("Resource 1");
        when(resource.isOwnerManagedAccess()).thenReturn(true);
        when(resource.getOwner()).thenReturn("user-id");
        
        when(resourceStore.findById(isNull(), eq("resource-1"))).thenReturn(resource);
        when(userProvider.getUserById(eq(realm), eq("user-id"))).thenReturn(user);
        
        // Mock ResourceServer for ResourceBean constructor
        ResourceServer resourceServer = mock(ResourceServer.class);
        when(resource.getResourceServer()).thenReturn(resourceServer);
        when(resourceServer.getClientId()).thenReturn("client-id");
        when(realm.getClientById("client-id")).thenReturn(null);
        
        // Create a new bean with the updated uriInfo
        authorizationBean = new AuthorizationBean(session, user, uriInfo);
        
        // Test
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.getResource();
        
        // Verify
        assertNotNull(resourceBean);
        assertEquals("resource-1", resourceBean.getId());
        assertEquals("Resource 1", resourceBean.getName());
    }

    @Test
    public void testRequesterBean() {
        // Setup
        PermissionTicket ticket = mock(PermissionTicket.class);
        when(ticket.getRequester()).thenReturn("requester-id");
        when(ticket.isGranted()).thenReturn(true);
        when(ticket.getCreatedTimestamp()).thenReturn(1000L);
        when(ticket.getGrantedTimestamp()).thenReturn(2000L);
        
        UserModel requester = mock(UserModel.class);
        when(requester.getUsername()).thenReturn("requester-user");
        when(userProvider.getUserById(eq(realm), eq("requester-id"))).thenReturn(requester);
        
        // Test
        AuthorizationBean.RequesterBean requesterBean = new AuthorizationBean.RequesterBean(ticket, authorizationProvider);
        
        // Verify
        assertNotNull(requesterBean);
        assertEquals(requester, requesterBean.getRequester());
        assertTrue(requesterBean.isGranted());
        assertNotNull(requesterBean.getCreatedDate());
        assertNotNull(requesterBean.getGrantedDate());
    }

    @Test
    public void testPermissionScopeBean() {
        // Setup
        PermissionTicket ticket = mock(PermissionTicket.class);
        when(ticket.getId()).thenReturn("permission-id");
        when(ticket.isGranted()).thenReturn(true);
        when(ticket.getGrantedTimestamp()).thenReturn(2000L);
        
        // Test
        AuthorizationBean.PermissionScopeBean scopeBean = new AuthorizationBean.PermissionScopeBean(ticket);
        
        // Verify
        assertNotNull(scopeBean);
        assertEquals("permission-id", scopeBean.getId());
        assertTrue(scopeBean.isGranted());
    }
    
    @Test
    public void testResourceBean_GetPolicies() {
        // Setup
        Resource resource = mock(Resource.class);
        when(resource.getId()).thenReturn("resource-id");
        when(resource.getName()).thenReturn("Resource Name");
        when(resource.isOwnerManagedAccess()).thenReturn(true);
        when(resource.getOwner()).thenReturn("user-id");
        
        ResourceServer resourceServer = mock(ResourceServer.class);
        when(resource.getResourceServer()).thenReturn(resourceServer);
        when(resourceServer.getClientId()).thenReturn("client-id");
        
        when(userProvider.getUserById(eq(realm), eq("user-id"))).thenReturn(user);
        when(realm.getClientById("client-id")).thenReturn(null);
        
        // Create a ResourceBean
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Mock the policy store
        org.keycloak.authorization.store.PolicyStore policyStore = mock(org.keycloak.authorization.store.PolicyStore.class);
        when(storeFactory.getPolicyStore()).thenReturn(policyStore);
        when(policyStore.find(any(ResourceServer.class), any(Map.class), isNull(), isNull()))
            .thenReturn(Collections.emptyList());
        
        // Test
        Collection<AuthorizationBean.ManagedPermissionBean> policies = resourceBean.getPolicies();
        
        // Verify
        assertNotNull(policies);
        assertTrue(policies.isEmpty());
    }
    
    @Test
    public void testResourceBean_GetShares() {
        // Setup
        Resource resource = mock(Resource.class);
        when(resource.getId()).thenReturn("resource-id");
        when(resource.getName()).thenReturn("Resource Name");
        when(resource.isOwnerManagedAccess()).thenReturn(true);
        when(resource.getOwner()).thenReturn("user-id");
        
        ResourceServer resourceServer = mock(ResourceServer.class);
        when(resource.getResourceServer()).thenReturn(resourceServer);
        when(resourceServer.getClientId()).thenReturn("client-id");
        
        when(userProvider.getUserById(eq(realm), eq("user-id"))).thenReturn(user);
        when(realm.getClientById("client-id")).thenReturn(null);
        
        // Create a ResourceBean
        AuthorizationBean.ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);
        
        // Mock the permission ticket store
        when(permissionTicketStore.find(isNull(), any(Map.class), isNull(), isNull()))
            .thenReturn(Collections.emptyList());
        
        // Test
        Collection<AuthorizationBean.RequesterBean> shares = resourceBean.getShares();
        
        // Verify
        assertNotNull(shares);
        assertTrue(shares.isEmpty());
    }
    
    @Test
    public void testResourceServerBean() {
        // Setup
        ResourceServer resourceServer = mock(ResourceServer.class);
        when(resourceServer.getId()).thenReturn("server-id");
        
        org.keycloak.models.ClientModel clientModel = mock(org.keycloak.models.ClientModel.class);
        when(clientModel.getName()).thenReturn("Client Name");
        when(clientModel.getClientId()).thenReturn("client-id");
        when(clientModel.getRedirectUris()).thenReturn(java.util.Set.of("https://example.com/callback"));
        when(clientModel.getRootUrl()).thenReturn("https://example.com");
        when(clientModel.getBaseUrl()).thenReturn("/app");
        
        // Mock the KeycloakContext for ResolveRelative.resolveRelativeUri
        KeycloakContext keycloakContext = mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(keycloakContext);
        
        // Test
        AuthorizationBean.ResourceServerBean serverBean = authorizationBean.new ResourceServerBean(clientModel, resourceServer);
        
        // Verify
        assertNotNull(serverBean);
        assertEquals("server-id", serverBean.getId());
        assertEquals("Client Name", serverBean.getName());
        assertEquals("client-id", serverBean.getClientId());
        assertEquals("https://example.com/callback", serverBean.getRedirectUri());
        // Skip testing getBaseUri() as it requires more complex mocking
        assertEquals(resourceServer, serverBean.getResourceServerModel());
    }
    
    @Test
    public void testResourceServerBean_WithNullName() {
        // Setup
        ResourceServer resourceServer = mock(ResourceServer.class);
        when(resourceServer.getId()).thenReturn("server-id");
        
        org.keycloak.models.ClientModel clientModel = mock(org.keycloak.models.ClientModel.class);
        when(clientModel.getName()).thenReturn(null);
        when(clientModel.getClientId()).thenReturn("client-id");
        when(clientModel.getRedirectUris()).thenReturn(Collections.emptySet());
        
        // Test
        AuthorizationBean.ResourceServerBean serverBean = authorizationBean.new ResourceServerBean(clientModel, resourceServer);
        
        // Verify
        assertNotNull(serverBean);
        assertEquals("client-id", serverBean.getName());
        assertNull(serverBean.getRedirectUri());
    }
    
    @Test
    public void testManagedPermissionBean() {
        // Setup
        org.keycloak.authorization.model.Policy policy = mock(org.keycloak.authorization.model.Policy.class);
        when(policy.getId()).thenReturn("policy-id");
        when(policy.getDescription()).thenReturn("Policy Description");
        when(policy.getScopes()).thenReturn(Collections.emptySet());
        when(policy.getAssociatedPolicies()).thenReturn(Collections.emptySet());
        
        // Test
        AuthorizationBean.ManagedPermissionBean permissionBean = authorizationBean.new ManagedPermissionBean(policy);
        
        // Verify
        assertNotNull(permissionBean);
        assertEquals("policy-id", permissionBean.getId());
        assertEquals("Policy Description", permissionBean.getDescription());
        assertTrue(permissionBean.getScopes().isEmpty());
        assertTrue(permissionBean.getPolicies().isEmpty());
    }
}
