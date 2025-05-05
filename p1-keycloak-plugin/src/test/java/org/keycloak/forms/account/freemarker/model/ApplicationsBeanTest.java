package org.keycloak.forms.account.freemarker.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserConsentModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.services.resources.admin.permissions.ClientPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.RealmsPermissionEvaluator;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ApplicationsBeanTest {

    @Mock
    private KeycloakSession keycloakSession;
    @Mock
    private RealmModel realm;
    @Mock
    private UserModel user;
    @Mock
    private ClientModel client;
    @Mock
    private KeycloakContext context;
    @Mock
    private org.keycloak.models.KeycloakUriInfo keycloakUriInfo;
    @Mock
    private org.keycloak.models.UserProvider userProvider;

    private Map<String, ClientScopeModel> clientScopeModelMap;

    @BeforeEach
    void setUp() throws URISyntaxException {
        URI uri = new URI("http://ApplicationBeanTest.com");

        // Stub keycloakSession.sessions() to return a non-null UserSessionProvider.
        UserSessionProvider usp = mock(UserSessionProvider.class);
        when(keycloakSession.sessions()).thenReturn(usp);
        // Stub getOfflineUserSessionsStream() to return an empty stream.
        when(usp.getOfflineUserSessionsStream(realm, user)).thenReturn(Stream.empty());

        when(keycloakSession.users()).thenReturn(userProvider);
        when(keycloakSession.getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(keycloakUriInfo);
        when(context.getUri(any())).thenReturn(keycloakUriInfo);
        when(keycloakUriInfo.getBaseUri()).thenReturn(uri);

        // Mock realm: for example, offline_access role.
        RoleModel offlineAccessRole = mock(RoleModel.class);
        when(realm.getRole("offline_access")).thenReturn(offlineAccessRole);

        clientScopeModelMap = new HashMap<>();
        clientScopeModelMap.put("scope1", mock(ClientScopeModel.class));
        clientScopeModelMap.put("scope2", mock(ClientScopeModel.class));
    }

    @Test
    void testAdminClient() {
        // Condition 1
        when(client.getClientId()).thenReturn(Constants.ADMIN_CLI_CLIENT_ID);
        assertTrue(ApplicationsBean.isAdminClient(client));

        // Condition 2
        when(client.getClientId()).thenReturn(Constants.ADMIN_CONSOLE_CLIENT_ID);
        assertTrue(ApplicationsBean.isAdminClient(client));

        // Condition 3
        when(client.getClientId()).thenReturn("");
        assertFalse(ApplicationsBean.isAdminClient(client));
    }

    @Test
    void testApplicationBeanGenericCase() throws Exception {
        ApplicationsBean applicationsBean = new ApplicationsBean(keycloakSession, realm, user);
        assertNotNull(applicationsBean.getApplications(), "getApplications() should not return null");
    }

    @Test
    void testApplicationEntryInnerClass() throws Exception {
        when(client.getRootUrl()).thenReturn("http://example.com");
        when(client.getBaseUrl()).thenReturn("/app");

        List<RoleModel> realmRolesAvailableList = Collections.singletonList(mock(RoleModel.class));
        MultivaluedHashMap<String, ApplicationsBean.ClientRoleEntry> resourceRolesAvailableMap = new MultivaluedHashMap<>();
        List<String> clientScopesGrantedList = Arrays.asList("scope1", "scope2");
        List<String> additionalGrantsList = Arrays.asList("grant1", "grant2");

        ApplicationsBean.ApplicationEntry applicationEntry = new ApplicationsBean.ApplicationEntry(
                keycloakSession,
                realmRolesAvailableList,
                resourceRolesAvailableMap,
                client,
                clientScopesGrantedList,
                additionalGrantsList
        );

        assertEquals("http://example.com/app", applicationEntry.getEffectiveUrl(), "Effective URL mismatch");
        assertEquals(client, applicationEntry.getClient(), "Client mismatch");
        assertEquals(realmRolesAvailableList, applicationEntry.getRealmRolesAvailable(), "Realm roles mismatch");
        assertEquals(resourceRolesAvailableMap, applicationEntry.getResourceRolesAvailable(), "Resource roles mismatch");
        assertEquals(clientScopesGrantedList, applicationEntry.getClientScopesGranted(), "Granted scopes mismatch");
        assertEquals(additionalGrantsList, applicationEntry.getAdditionalGrants(), "Additional grants mismatch");
    }

    @Test
    void testClientRoleEntryInnerClass() {
        String clientID = "clientID";
        String clientName = "clientName";
        String roleName = "roleName";
        String roleDescription = "roleDescription";

        ApplicationsBean.ClientRoleEntry clientRoleEntry = new ApplicationsBean.ClientRoleEntry(
                clientID, clientName, roleName, roleDescription
        );

        assertEquals(clientID, clientRoleEntry.getClientId(), "clientId mismatch");
        assertEquals(clientName, clientRoleEntry.getClientName(), "clientName mismatch");
        assertEquals(roleName, clientRoleEntry.getRoleName(), "roleName mismatch");
        assertEquals(roleDescription, clientRoleEntry.getRoleDescription(), "roleDescription mismatch");
    }

    @Test
    void getApplicationsConditionsTest1() throws Exception {
        ClientModel client1 = mock(ClientModel.class);
        ClientModel client2 = mock(ClientModel.class);

        when(client1.getId()).thenReturn("client1:client1:client1");
        when(client1.getClientId()).thenReturn(Constants.ADMIN_CONSOLE_CLIENT_ID);
        when(client1.isBearerOnly()).thenReturn(false);
        when(client1.getClientScopes(eq(true))).thenReturn(clientScopeModelMap);
        when(client1.getClientScopes(eq(false))).thenReturn(clientScopeModelMap);
        when(client1.isConsentRequired()).thenReturn(true);

        when(client2.getId()).thenReturn("client2:client2:client2");
        when(client2.getClientId()).thenReturn(Constants.SKIP_LOGOUT);
        when(client2.isBearerOnly()).thenReturn(false);
        when(client2.getClientScopes(eq(true))).thenReturn(clientScopeModelMap);
        when(client2.getClientScopes(eq(false))).thenReturn(clientScopeModelMap);
        when(client2.isConsentRequired()).thenReturn(false);

        Stream<ClientModel> clientsStream = Stream.of(client1, client2);

        RoleModel roleModel1 = mock(RoleModel.class);
        when(roleModel1.getContainer()).thenReturn(realm);

        RoleModel roleModel2 = mock(RoleModel.class);
        when(roleModel2.getContainer()).thenReturn(client);

        Set<RoleModel> roleModelSet = new HashSet<>();
        roleModelSet.add(roleModel1);
        roleModelSet.add(roleModel2);

        try (var mockedAdminPermissions = mockStatic(AdminPermissions.class);
             var mockedTokenManager = mockStatic(TokenManager.class)) {

            ClientPermissionEvaluator mockClientPermEval = mock(ClientPermissionEvaluator.class);
            AdminPermissionEvaluator mockAdminPermEval = mock(AdminPermissionEvaluator.class);

            mockedAdminPermissions.when(() -> AdminPermissions.evaluator(any(), any(), any()))
                    .thenReturn(mockAdminPermEval);
            when(mockAdminPermEval.clients()).thenReturn(mockClientPermEval);
            when(mockClientPermEval.canView(any())).thenReturn(true);
            mockedTokenManager.when(() -> TokenManager.getAccess(any(), any(), any()))
                              .thenReturn(roleModelSet);

            when(realm.getClientsStream()).thenReturn(clientsStream);
            when(realm.getName()).thenReturn("realm");
            when(realm.getClientByClientId(anyString())).thenReturn(client);

            ApplicationsBean applicationsBean = new ApplicationsBean(keycloakSession, realm, user);
            assertNotNull(applicationsBean.getApplications(), "Applications should not be null");
        }
    }

    @Test
    void getApplicationsConditionsTest2() throws Exception {
        ClientModel client1 = mock(ClientModel.class);
        ClientModel client2 = mock(ClientModel.class);

        when(client1.getId()).thenReturn("client1:client1:client1");
        when(client1.getClientId()).thenReturn(Constants.ADMIN_CONSOLE_CLIENT_ID);
        when(client1.isBearerOnly()).thenReturn(false);
        when(client1.getClientScopes(eq(true))).thenReturn(clientScopeModelMap);
        when(client1.getClientScopes(eq(false))).thenReturn(clientScopeModelMap);
        when(client1.isConsentRequired()).thenReturn(true);

        when(client2.getId()).thenReturn("client2:client2:client2");
        when(client2.getClientId()).thenReturn(Constants.SKIP_LOGOUT);
        when(client2.isBearerOnly()).thenReturn(false);
        when(client2.getClientScopes(eq(true))).thenReturn(clientScopeModelMap);
        when(client2.getClientScopes(eq(false))).thenReturn(clientScopeModelMap);
        when(client2.isConsentRequired()).thenReturn(false);

        Stream<ClientModel> clientsStream = Stream.of(client1, client2);

        try (var mockedAdminPermissions = mockStatic(AdminPermissions.class)) {
            ClientPermissionEvaluator mockClientPermEval = mock(ClientPermissionEvaluator.class);
            AdminPermissionEvaluator mockAdminPermEval = mock(AdminPermissionEvaluator.class);

            mockedAdminPermissions.when(() -> AdminPermissions.evaluator(any(), any(), any()))
                    .thenReturn(mockAdminPermEval);
            when(mockAdminPermEval.clients()).thenReturn(mockClientPermEval);
            when(mockClientPermEval.canView(any())).thenReturn(false);

            when(realm.getClientsStream()).thenReturn(clientsStream);
            when(realm.getName()).thenReturn("realm");
            when(realm.getClientByClientId(anyString())).thenReturn(client);

            ApplicationsBean applicationsBean = new ApplicationsBean(keycloakSession, realm, user);
            assertNotNull(applicationsBean.getApplications(), "Applications should not be null");
        }
    }
}
