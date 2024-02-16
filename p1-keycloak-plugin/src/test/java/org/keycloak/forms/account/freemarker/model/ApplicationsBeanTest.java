package org.keycloak.forms.account.freemarker.model;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.KeycloakUriInfo;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.models.*;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.services.resources.admin.permissions.RealmsPermissionEvaluator;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.powermock.api.mockito.PowerMockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ UserSessionManager.class, AdminPermissions.class,
})
public class ApplicationsBeanTest {

    private KeycloakSession keycloakSession;
    private UserSessionProvider userSessionProvider;
    private RealmModel realm;
    private UserModel user;
    private ClientModel client;
    private KeycloakContext context;
    private KeycloakUriInfo keycloakUriInfo;
    private UserProvider userProvider;

    @Before
    public void setUp() throws URISyntaxException {
        URI uri = new URI("ApplicationBeanTest.com");

        keycloakSession = mock(KeycloakSession.class);
        userSessionProvider = mock(UserSessionProvider.class);
        realm = mock(RealmModel.class);
        user = mock(UserModel.class);
        client = mock(ClientModel.class);
        context = mock(KeycloakContext.class);
        keycloakUriInfo = mock(KeycloakUriInfo.class);
        userProvider = mock(UserProvider.class);

        // Mocking the behavior of relevant methods in KeycloakSession and RealmModel
        when(keycloakSession.sessions()).thenReturn(userSessionProvider);
        when(keycloakSession.users()).thenReturn(userProvider);
        when(keycloakSession.getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(keycloakUriInfo);
        when(context.getUri(any())).thenReturn(keycloakUriInfo);
        when(keycloakUriInfo.getBaseUri()).thenReturn(uri);

        // realm
        when(realm.getRole("offline_access")).thenReturn(mock(RoleModel.class));
    }

    @Test
    public void testAdminClientTrue(){
        when(client.getClientId()).thenReturn(Constants.ADMIN_CLI_CLIENT_ID);
        assertTrue(ApplicationsBean.isAdminClient(client));
    }

    @Test
    public void testAdminClientFalse(){
        when(client.getClientId()).thenReturn("");
        assertFalse(ApplicationsBean.isAdminClient(client));
    }

    @Test
    public void testApplicationBeanGenericCase() throws Exception {
        when(client.getClientId()).thenReturn(Constants.ADMIN_CONSOLE_CLIENT_ID);
        assertTrue(ApplicationsBean.isAdminClient(client));

        Set<ClientModel> clientSet = new HashSet<>();
        clientSet.add(client);

        // Mocking the behavior of relevant methods in UserSessionManager
        UserSessionManager userSessionManager = mock(UserSessionManager.class);
        whenNew(UserSessionManager.class).withArguments(keycloakSession).thenReturn(userSessionManager);
        when(userSessionManager.findClientsWithOfflineToken(realm, user)).thenReturn(clientSet);

        ApplicationsBean applicationsBean = new ApplicationsBean(keycloakSession, realm, user);

        assertNotNull(applicationsBean.getApplications());
    }

    @Test
    public void testApplicationEntryInnerClass() throws Exception {

        // Mock getRootUrl() and getBaseUrl() methods in ClientModel
        when(client.getRootUrl()).thenReturn("http://example.com");
        when(client.getBaseUrl()).thenReturn("/app");

        // Create an instance of ApplicationEntry
        List<RoleModel> realmRolesAvailableList = Arrays.asList(mock(RoleModel.class));
        MultivaluedHashMap<String, ApplicationsBean.ClientRoleEntry> resourceRolesAvailableMap = new MultivaluedHashMap<>();
        List<String> clientScopesGrantedList = Arrays.asList("scope1", "scope2");
        List<String> additionalGrantsList = Arrays.asList("grant1", "grant2");

        ApplicationsBean.ApplicationEntry applicationEntry = new ApplicationsBean.ApplicationEntry(
                keycloakSession, realmRolesAvailableList, resourceRolesAvailableMap, client,
                clientScopesGrantedList, additionalGrantsList);

        // Test methods
        assertEquals("http://example.com/app", applicationEntry.getEffectiveUrl());
        assertEquals(client, applicationEntry.getClient());
        assertEquals(realmRolesAvailableList, applicationEntry.getRealmRolesAvailable());
        assertEquals(resourceRolesAvailableMap, applicationEntry.getResourceRolesAvailable());
        assertEquals(clientScopesGrantedList, applicationEntry.getClientScopesGranted());
        assertEquals(additionalGrantsList, applicationEntry.getAdditionalGrants());

    }

    @Test
    public void testClientRoleEntryInnerClass() {

        String clientID = "clientID";
        String clientName = "clientName";
        String roleName = "roleName";
        String roleDescription = "roleDescription";

        ApplicationsBean.ClientRoleEntry clientRoleEntry = new ApplicationsBean.ClientRoleEntry(clientID, clientName, roleName, roleDescription);

        assertEquals(clientID, clientRoleEntry.getClientId());
        assertEquals(clientName, clientRoleEntry.getClientName());
        assertEquals(roleName, clientRoleEntry.getRoleName());
        assertEquals(roleDescription, clientRoleEntry.getRoleDescription());
    }

    @Test
    public void getApplicationsConditionsTest() throws Exception {
        mockStatic(AdminPermissions.class);

        when(AdminPermissions.realms(any(), any(), any())).thenReturn(mock(RealmsPermissionEvaluator.class));
        when(AdminPermissions.realms(any(), any(), any()).isAdmin()).thenReturn(true);

        // mocks
        Map<String, ClientScopeModel> clientScopeModelMap = new HashMap<>();
        clientScopeModelMap.put("scope1", mock(ClientScopeModel.class));
        clientScopeModelMap.put("scope2", mock(ClientScopeModel.class));

        // clientModel
        ClientModel client1 = mock(ClientModel.class);
        ClientModel client2 = mock(ClientModel.class);

        when(client1.getId()).thenReturn("client1:client1:client1");
        when(client2.getId()).thenReturn("client2:client2:client2");
        when(client1.getClientId()).thenReturn(Constants.ADMIN_CONSOLE_CLIENT_ID);
        when(client2.getClientId()).thenReturn(Constants.ADMIN_CONSOLE_CLIENT_ID);
        when(client1.isBearerOnly()).thenReturn(false);
        when(client2.isBearerOnly()).thenReturn(true);
        when(client1.getClientScopes(eq(true))).thenReturn(clientScopeModelMap);
        when(client1.getClientScopes(eq(false))).thenReturn(clientScopeModelMap);
        when(client2.getClientScopes(eq(true))).thenReturn(clientScopeModelMap);
        when(client2.getClientScopes(eq(false))).thenReturn(clientScopeModelMap);

        // Stream clientModel
        Stream<ClientModel> clientsStream = Stream.of(client1, client2);

        // UserConsentModel
        UserConsentModel consent1 = mock(UserConsentModel.class);
        UserConsentModel consent2 = mock(UserConsentModel.class);

        when(consent1.getClient()).thenReturn(client1);
        when(consent2.getClient()).thenReturn(client2);

        Stream<UserConsentModel> userContentModelStream = Stream.of(consent1, consent2);

        // userProvider
        when(userProvider.getConsentsStream(any(), any())).thenReturn(userContentModelStream);

        // realm
        when(realm.getClientsStream()).thenReturn(clientsStream);
        when(realm.getName()).thenReturn("realm");
        when(realm.getClientByClientId(anyString())).thenReturn(client);

        // client
        when(client.getClientId()).thenReturn(Constants.SKIP_LOGOUT);

        // constructor
        ApplicationsBean applicationsBean = new ApplicationsBean(keycloakSession, realm, user);

        // condition
        assertNotNull(applicationsBean.getApplications());
    }
}
