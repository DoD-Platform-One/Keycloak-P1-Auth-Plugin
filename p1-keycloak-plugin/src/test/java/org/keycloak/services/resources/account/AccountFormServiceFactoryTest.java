package org.keycloak.services.resources.account;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.resteasy.core.ResteasyContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.cookie.CookieProvider;
import org.keycloak.cookie.CookieType;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.forms.account.AccountProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.AccountResourceProvider;
import org.keycloak.services.resource.AccountResourceProviderFactory;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.userprofile.UserProfileProvider;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.URI;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Demonstrates fixing the NullPointerException on HttpHeaders.getRequestHeaders()
 * by ensuring KeycloakContext and/or ResteasyContext return a non-null HttpHeaders.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT) // so we don't fail on "unused" stubbings
public class AccountFormServiceFactoryTest {

    // Mocks for providers, sessions, etc.
    @Mock private AccountProvider accountProvider;
    @Mock private EventStoreProvider eventStoreProvider;
    @Mock private UserProfileProvider userProfileProvider;
    @Mock private AuthorizationProvider authorizationProvider;
    @Mock private RealmModel realmModel;
    @Mock private ClientModel clientModel;
    @Mock private KeycloakSession session;
    @Mock private KeycloakContext keycloakContext;
    @Mock private ClientConnection clientConnection;
    @Mock private KeycloakUriInfo keycloakUriInfo;
    @Mock private CookieProvider cookieProvider;

    @InjectMocks
    private AccountFormServiceFactory accountFormServiceFactory;

    @BeforeEach
    public void setUp() {
        // 1) Provide a mock KeycloakContext and stub realm/client
        when(session.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getRealm()).thenReturn(realmModel);
        when(realmModel.getClientByClientId(any())).thenReturn(clientModel);
        when(clientModel.isEnabled()).thenReturn(true);

        // 2) Stub sessionFactory
        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(sessionFactory.getProviderFactoriesStream(any())).thenReturn(Stream.empty());

        // 3) Stub CookieProvider (used by Keycloak)
        when(session.getProvider(CookieProvider.class)).thenReturn(cookieProvider);
        when(cookieProvider.get(any(CookieType.class))).thenReturn(null);

        // 4) Stub other providers obtained from session
        when(session.getProvider(AccountProvider.class)).thenReturn(accountProvider);
        when(session.getProvider(EventStoreProvider.class)).thenReturn(eventStoreProvider);
        when(session.getProvider(UserProfileProvider.class)).thenReturn(userProfileProvider);
        when(session.getProvider(AuthorizationProvider.class)).thenReturn(authorizationProvider);

        // 5) Stub chainable methods on AccountProvider
        when(accountProvider.setRealm(any(RealmModel.class))).thenReturn(accountProvider);
        when(accountProvider.setUriInfo(any(KeycloakUriInfo.class))).thenReturn(accountProvider);
        when(accountProvider.setHttpHeaders(any(HttpHeaders.class))).thenReturn(accountProvider);

        // 6) Stub KeycloakContext so it returns a client connection and UriInfo
        when(keycloakContext.getConnection()).thenReturn(clientConnection);
        when(clientConnection.getRemoteAddr()).thenReturn("127.0.0.1");
        when(keycloakContext.getUri()).thenReturn(keycloakUriInfo);
        when(keycloakUriInfo.getBaseUri()).thenReturn(URI.create("http://example.com"));

        // 7) Provide a mock HttpHeaders and push it into ResteasyContext.
        // Remove the deprecated usage of getContextObject().
        HttpHeaders mockHeaders = mock(HttpHeaders.class);
        MultivaluedMap<String, String> requestHeaders = new MultivaluedHashMap<>();
        when(mockHeaders.getRequestHeaders()).thenReturn(requestHeaders);
        ResteasyContext.clearContextData();
        ResteasyContext.pushContext(HttpHeaders.class, mockHeaders);
        // Optionally push a mock HttpRequest if needed:
        HttpRequest mockRequest = mock(HttpRequest.class);
        ResteasyContext.pushContext(HttpRequest.class, mockRequest);
    }


    @Test
    public void testGetId() {
        // Basic test: no NPE expected
        assertEquals(AccountFormServiceFactory.ID, accountFormServiceFactory.getId());
    }

    @Test
    public void testGetAccountManagementClient_Success() {
        // Should retrieve the mocked, enabled client
        ClientModel result = accountFormServiceFactory.getAccountManagementClient(realmModel);
        assertEquals(clientModel, result, "Should return the same mocked clientModel");
    }

    @Test
    public void testGetAccountManagementClient_ClientNull() {
        // If getClientByClientId returns null, NotFoundException is expected
        when(realmModel.getClientByClientId(anyString())).thenReturn(null);

        assertThrows(NotFoundException.class,
                     () -> accountFormServiceFactory.getAccountManagementClient(realmModel));
    }

    @Test
    public void testGetAccountManagementClient_ClientNotEnabled() {
        // If the client is disabled, NotFoundException is expected
        when(clientModel.isEnabled()).thenReturn(false);

        assertThrows(NotFoundException.class,
                     () -> accountFormServiceFactory.getAccountManagementClient(realmModel));
    }

    @Test
    public void testCreate() {
        // The big test that used to throw NPE on headers.getRequestHeaders():
        AccountResourceProvider provider = accountFormServiceFactory.create(session);
        assertNotNull(provider, "create(...) should return a non-null AccountResourceProvider");
        assertTrue(provider instanceof AccountFormService, "Expected an AccountFormService");
    }

    @Test
    public void testLifecycleMethods() {
        accountFormServiceFactory.init(mock(Config.Scope.class));
        accountFormServiceFactory.postInit(mock(KeycloakSessionFactory.class));
        accountFormServiceFactory.close();
        // No exceptions expected
    }
}
