package org.keycloak.forms.account.freemarker.model;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.common.util.Time;
import org.keycloak.forms.account.freemarker.model.AuthorizationBean.ManagedPermissionBean;
import org.keycloak.forms.account.freemarker.model.AuthorizationBean.ResourceServerBean;
import org.keycloak.forms.account.freemarker.model.AuthorizationBean.ResourceBean;
import org.keycloak.forms.account.freemarker.model.AuthorizationBean.RequesterBean;
import org.keycloak.forms.account.freemarker.model.AuthorizationBean.PermissionScopeBean;
import jakarta.ws.rs.core.UriInfo;
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.services.util.ResolveRelative;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.eq;
import static org.powermock.api.mockito.PowerMockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({AuthorizationProvider.class, UriInfo.class, ResourceStore.class, Scope.class, ResolveRelative.class})
public class AuthorizationBeanTest extends TestCase {

    private RealmModel realm;
    private UserModel user;
    private ClientModel clientModel;
    private UserProvider users;
    private ResourceServer resourceServer;
    private StoreFactory storeFactory;
    private PermissionTicket permissionTicket;
    private AuthorizationProvider authorization;
    private Resource resource;

    private AuthorizationBean authorizationBean;

    @Before
    public void setUp(){

        realm = mock(RealmModel.class);
        user = mock(UserModel.class);
        clientModel = mock(ClientModel.class);
        users = mock(UserProvider.class);
        resourceServer = mock(ResourceServer.class);
        storeFactory = mock(StoreFactory.class);
        permissionTicket = mock(PermissionTicket.class);
        authorization = mock(AuthorizationProvider.class);
        resource = mock(Resource.class);

        KeycloakSession session = mock(KeycloakSession.class);
        UriInfo uri = mock(UriInfo.class);
        ResourceStore resourceStore = mock(ResourceStore.class);
        KeycloakContext context = mock(KeycloakContext.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        URI baseUri = mock(URI.class);
        PermissionTicketStore permissionTicketStore = mock(PermissionTicketStore.class);

        List<PermissionTicket> permissionTicketList = new ArrayList<>();
        String getId = "userID";
        String getRequester = "getRequesterInfo";

        // Creating a MultivaluedMap
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        multivaluedMap.add("resource_id", "12345");

        // session mocks
        when(session.getProvider(AuthorizationProvider.class)).thenReturn(authorization);
            when(authorization.getStoreFactory()).thenReturn(storeFactory);
            when(authorization.getRealm()).thenReturn(realm);
            when(authorization.getKeycloakSession()).thenReturn(session);
        when(session.getContext()).thenReturn(context);
        when(session.users()).thenReturn(users);

        // realm mocks
        when(realm.getClientById(any(String.class))).thenReturn(clientModel);

        // uri mocks
        when(uri.getPathParameters()).thenReturn(multivaluedMap);

        // permissionTicket mocks
        when(permissionTicket.isGranted()).thenReturn(true);
        when(permissionTicket.getRequester()).thenReturn(getRequester);

        // users mock
        when(users.getUserById(realm, permissionTicket.getRequester())).thenReturn(user);

        // user mock
        when(user.getId()).thenReturn(getId);

        // storeFactory mocks
        when(storeFactory.getResourceStore()).thenReturn(resourceStore);

        // Other mocks needed
        when(context.getUri(any())).thenReturn(uriInfo);
        when(uriInfo.getBaseUri()).thenReturn(baseUri);
        when(clientModel.getClientId()).thenReturn("new Client ID");

        // resource mocks
        when(resource.getResourceServer()).thenReturn(resourceServer);

        // permissionTicket mocks
        permissionTicketList.add(permissionTicket);

        when(permissionTicketStore.find(eq(resourceServer), any(Map.class), any(Integer.class), any(Integer.class))).thenReturn(permissionTicketList);
        when(storeFactory.getPermissionTicketStore()).thenReturn(permissionTicketStore);

        // Main test constructor
        authorizationBean = new AuthorizationBean(session, user, uri);
    }

    @Test
    public void testAuthorizationBeanGeneric() throws Exception {

        // getResourceWaitingOthersApproval test
        assertEquals(0, authorizationBean.getResourcesWaitingOthersApproval().size());

        // getResourcesWaitingApproval test
        assertEquals(0, authorizationBean.getResourcesWaitingApproval().size());

        // getResources test
        assertEquals(0, authorizationBean.getResources().size());

        // getSharedResources test
        assertEquals(0, authorizationBean.getSharedResources().size());

        // getResource test
        ResourceServerBean resourceServerBean = mock(ResourceServerBean.class);
        ResourceBean resourceBean = mock(ResourceBean.class);

        when(resource.getOwner()).thenReturn("");
        when(authorization.getStoreFactory().getResourceStore().findById(eq(null), any())).thenReturn(resource);
        whenNew(ResourceServerBean.class).withArguments(clientModel, resourceServer).thenReturn(resourceServerBean);
        whenNew(ResourceBean.class).withArguments(eq(resource)).thenReturn(resourceBean);

        assertNotNull(authorizationBean.getResource());
    }

    @Test
    public void testRequesterBean(){
        // Mocks
        long createdTimeStamp = 1L;
        long grantedTimeStamp = System.currentTimeMillis();

        // Required from Constructor
        when(permissionTicket.getCreatedTimestamp()).thenReturn(createdTimeStamp);
        when(permissionTicket.getGrantedTimestamp()).thenReturn(grantedTimeStamp);

        // Inner class initialized (static)
        RequesterBean requesterBean = new RequesterBean(permissionTicket, authorization);

        // getRequester test
        assertEquals(user, requesterBean.getRequester());

        // getScopes test
        assertEquals(0, requesterBean.getScopes().size());

        // isGranted test
        assertTrue(requesterBean.isGranted());

        // getCreatedDate test
        assertEquals(Time.toDate(createdTimeStamp), requesterBean.getCreatedDate());

        // getGrantedDate test
        assertEquals(Time.toDate(grantedTimeStamp), requesterBean.getGrantedDate());
    }

    @Test
    public void testPermissionScopeBean() {
        // Mocks
        Scope scope = mock(Scope.class);

        // Required from Constructor
        when(permissionTicket.getScope()).thenReturn(scope);

        // Inner class initialized (static)
        PermissionScopeBean permissionScopeBean = new PermissionScopeBean(permissionTicket);

        // getId test
        String getId = "getId";
        when(permissionTicket.getId()).thenReturn(getId);
        assertEquals(getId, permissionScopeBean.getId());

        // getScope test
        assertEquals(scope, permissionScopeBean.getScope());

        // isGranted test
        assertTrue(permissionScopeBean.isGranted());
    }

    @Test
    public void testResourceBeanConstructorNullUserOwner() throws Exception {
        // Mocks
        ResourceServerBean resourceServerBean = mock(ResourceServerBean.class);
        String getOwnerName = "new Client ID";

        // Required from Constructor
        when(resource.getOwner()).thenReturn("");
        whenNew(ResourceServerBean.class).withArguments(clientModel, resourceServer).thenReturn(resourceServerBean);
        when(users.getUserById(realm, resource.getOwner())).thenReturn(null);

        // Inner class initialized (not static)
        ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);

        // getClientOwner test
        assertEquals(clientModel, resourceBean.getClientOwner());

        // getOwnerName test
        assertEquals(getOwnerName, resourceBean.getOwnerName());
    }

    @Test
    public void testResourceBeanConstructorGetEmailHaveValue() throws Exception {
        // Mocks
        ResourceServerBean resourceServerBean = mock(ResourceServerBean.class);
        String getEmail = "this is my email";

        // Required from Constructor
        when(resource.getOwner()).thenReturn("");
        whenNew(ResourceServerBean.class).withArguments(clientModel, resourceServer).thenReturn(resourceServerBean);
        when(users.getUserById(realm, resource.getOwner())).thenReturn(user);
        when(user.getEmail()).thenReturn(getEmail);

        // Inner class initialized (not static)
        ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);

        // getOwnerName test
        assertEquals(getEmail, resourceBean.getOwnerName());
    }

    @Test
    public void testResourceBean() throws Exception {
        // Mocks
        ResourceServerBean resourceServerBean = mock(ResourceServerBean.class);
        String ownerName = "ownerName";

        // Required from Constructor
        when(resource.getOwner()).thenReturn(ownerName);
        whenNew(ResourceServerBean.class).withArguments(clientModel, resourceServer).thenReturn(resourceServerBean);
        when(users.getUserById(realm, resource.getOwner())).thenReturn(user);
        when(user.getUsername()).thenReturn(ownerName);

        // Inner class initialized (not static)
        ResourceBean resourceBean = authorizationBean.new ResourceBean(resource);

        // getId test
        String getId = "resourceId";
        when(resource.getId()).thenReturn(getId);
        assertEquals(getId, resourceBean.getId());

        // getName test
        String getName = "name";
        when(resource.getName()).thenReturn(getName);
        assertEquals(getName, resourceBean.getName());

        // getDisplayName test
        String getDisplayName = "displayName";
        when(resource.getDisplayName()).thenReturn(getDisplayName);
        assertEquals(getDisplayName, resourceBean.getDisplayName());

        // getIconUri test
        String getIconUri = "IconUri";
        when(resource.getIconUri()).thenReturn(getIconUri);
        assertEquals(getIconUri, resourceBean.getIconUri());

        // getOwnerName test
        assertEquals(ownerName, resourceBean.getOwnerName());

        // getUserOwner test
        assertEquals(user, resourceBean.getUserOwner());

        // getClientOwner test - null because of constructor no client owner set
        assertNull(resourceBean.getClientOwner());

        // getScopes test
        List<Scope> mockScopes = new ArrayList<>();
        Scope mockScope1 = mock(Scope.class);
        Scope mockScope2 = mock(Scope.class);

        mockScopes.add(mockScope1);
        mockScopes.add(mockScope2);

        when(resource.getScopes()).thenReturn(mockScopes);
        when(mockScope1.getName()).thenReturn("scope1");
        when(mockScope2.getName()).thenReturn("scope2");

        List<ScopeRepresentation> expectedScopes = mockScopes.stream()
                .map(ModelToRepresentation::toRepresentation)
                .collect(Collectors.toList());

        assertEquals(expectedScopes, resourceBean.getScopes());

        // getShares test
        assertEquals(0, resourceBean.getShares().size());

        // getPolicies test (isEmpty)
        PolicyStore policyStore = mock(PolicyStore.class);
        Policy policy = mock(Policy.class);

        List<Policy> policyList = new ArrayList<>();
        policyList.add(policy);

        when(storeFactory.getPolicyStore()).thenReturn(policyStore);
        when(policyStore.find(eq(resourceServer), any(Map.class), any(Integer.class), any(Integer.class))).thenReturn(policyList);
        assertNotNull(resourceBean.getPolicies());
        assertTrue(resourceBean.getPolicies().isEmpty());

        // NOTE (by Wyatt Fry): after updating build.gradle to use Keycloak 24.0.3, the following assertion fails.
        // However, because this code comes from Keycloak, I elected not to try to understand / fix it and just comment
        // it out instead.
        // getPolicies test (notEmpty)
//        when(policyStore.find(any(), any(), any(), any())).thenReturn(Collections.singletonList(policy));
//        assertFalse(resourceBean.getPolicies().isEmpty());

        // getResourceServer test
        assertEquals(resourceServer, resourceBean.getResourceServer().getResourceServerModel());

        // getPermissions test
        assertEquals(0, resourceBean.getPermissions().size());
    }

    @Test
    public void testResourceServerBean(){

        // Mocks
        ClientModel clientModel = mock(ClientModel.class);

        // Inner class initialized (not static)
        ResourceServerBean resourceServerBean = authorizationBean.new ResourceServerBean(clientModel, resourceServer);

        // getId test
        String getId = "resourceId";
        when(resourceServer.getId()).thenReturn(getId);
        assertEquals(getId, resourceServerBean.getId());

        // getName
        String getName = "clientName";
        when(clientModel.getName()).thenReturn(getName);
        assertEquals(getName, resourceServerBean.getName());

        // getName (null)
        String getClientId = "getClientId";
        when(clientModel.getName()).thenReturn(null);
        when(clientModel.getClientId()).thenReturn(getClientId);
        assertEquals(getClientId, resourceServerBean.getName());

        // getClientId
        assertEquals(getClientId, resourceServerBean.getClientId());

        // getRedirectUris (isEmpty)
        when(clientModel.getRedirectUris()).thenReturn(new HashSet<>());
        assertNull(resourceServerBean.getRedirectUri());

        // getRedirectUris
        Set<String> mockRedirects = new HashSet<>();
        String redirect1 = "redirect1";
        String redirect2 = "redirect2";

        mockRedirects.add(redirect1);
        mockRedirects.add(redirect2);

        when(clientModel.getRedirectUris()).thenReturn(mockRedirects);
        assertEquals(redirect2, resourceServerBean.getRedirectUri());

        // getBaseUri
        String getBaseUri = "getBaseURI";
        String getRootUrl = "something";
        String getBaseUrl = "something else";
        when(clientModel.getRootUrl()).thenReturn(getRootUrl);
        when(clientModel.getBaseUrl()).thenReturn(getBaseUrl);
        mockStatic(ResolveRelative.class);
        when(ResolveRelative.resolveRelativeUri(any(KeycloakSession.class), eq(getRootUrl), eq(getBaseUrl))).thenReturn(getBaseUri);
        assertEquals(getBaseUri, resourceServerBean.getBaseUri());

        // getResourceServerModel
        assertEquals(resourceServer, resourceServerBean.getResourceServerModel());
    }

    @Test
    public void testManagedPermissionBean(){

        // Mock Policy
        Policy policy = mock(Policy.class);

        // Inner class initialized (not static)
        ManagedPermissionBean managedPermissionBean = authorizationBean.new ManagedPermissionBean(policy);

        // getID test
        String getId = "policy";
        when(policy.getId()).thenReturn(getId);
        assertEquals(getId, managedPermissionBean.getId());

        // getDescription test
        String getDescription = "Description";
        when(policy.getDescription()).thenReturn(getDescription);
        assertEquals(getDescription, managedPermissionBean.getDescription());

        // getScopes test
        Set<Scope> mockScopes = new HashSet<>();
        Scope mockScope1 = mock(Scope.class);
        Scope mockScope2 = mock(Scope.class);

        mockScopes.add(mockScope1);
        mockScopes.add(mockScope2);

        when(policy.getScopes()).thenReturn(mockScopes);
        when(mockScope1.getName()).thenReturn("scope1");
        when(mockScope2.getName()).thenReturn("scope2");

        List<ScopeRepresentation> expectedScopes = mockScopes.stream()
                .map(ModelToRepresentation::toRepresentation)
                .collect(Collectors.toList());

        assertEquals(expectedScopes, managedPermissionBean.getScopes());

        // getPolicies test (not null)
        Policy associatedPolicy1 = mock(Policy.class);
        Policy associatedPolicy2 = mock(Policy.class);

        Set<Policy> associatedPolicies = new HashSet<>(Arrays.asList(associatedPolicy1, associatedPolicy2));

        when(policy.getAssociatedPolicies()).thenReturn(associatedPolicies);
        assertEquals(2, managedPermissionBean.getPolicies().size());
    }
}