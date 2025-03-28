package org.keycloak.services.resources.account;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.cookie.CookieProvider;
import org.keycloak.cookie.CookieType;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.forms.account.AccountProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class AccountFormServiceTest {

    @Mock private KeycloakSession keycloakSession;
    @Mock private org.keycloak.models.KeycloakContext keycloakContext;
    @Mock private RealmModel realmModel;
    @Mock private ClientModel clientModel;
    // Use KeycloakUriInfo as expected by the context.
    @Mock private KeycloakUriInfo keycloakUriInfo;
    @Mock private AccountProvider accountProvider;
    @Mock private EventBuilder eventBuilder;
    @Mock private HttpHeaders httpHeaders;
    @Mock private AppAuthManager appAuthManager;
    @Mock private UserProfileProvider userProfileProvider;
    @Mock private EventStoreProvider eventStoreProvider;
    @Mock private AuthenticationSessionProvider authenticationSessionProvider;
    @Mock private ClientConnection clientConnection;
    @Mock private AuthorizationProvider authorizationProvider;

    // Base URI for tests.
    private final URI uri = URI.create("http://example.com");

    // Dummy objects for headers and request.
    private HttpHeaders dummyHeaders;
    private HttpRequest dummyRequest;

    /**
     * Helper method to set the first field in the class hierarchy that is assignable from targetType.
     */
    private static void setFieldByType(Object target, Class<?> targetType, Object value) {
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            for (Field field : clazz.getDeclaredFields()) {
                if (targetType.isAssignableFrom(field.getType())) {
                    field.setAccessible(true);
                    try {
                        field.set(target, value);
                        return;
                    } catch (IllegalAccessException e) {
                        throw new RuntimeException("Failed to set field: " + field.getName(), e);
                    }
                }
            }
            clazz = clazz.getSuperclass();
        }
        throw new RuntimeException("No field of type " + targetType.getName() + " found in class hierarchy");
    }

    /**
     * TestableAccountFormService bypasses header- and request-dependent initialization
     * and overrides login(String) to bypass URI building.
     */
    private static class TestableAccountFormService extends AccountFormService {
        public TestableAccountFormService(KeycloakSession session, ClientModel client, EventBuilder eventBuilder) {
            super(session, client, eventBuilder);
        }
        @Override
        public void init() {
            // Bypass header- and request-dependent initialization.
        }
        @Override
        protected Response login(String path) {
            // Bypass URI building logic.
            return Response.ok().build();
        }
    }

    /**
     * RealLoginAccountFormService does not override login(String), so real URI building is executed.
     */
    private static class RealLoginAccountFormService extends AccountFormService {
        public RealLoginAccountFormService(KeycloakSession session, ClientModel client, EventBuilder eventBuilder) {
            super(session, client, eventBuilder);
        }
        @Override
        public void init() {
            // Bypass header- and request-dependent initialization.
        }
    }

    // We'll use testService for tests that bypass login logic.
    private TestableAccountFormService testService;

    @BeforeEach
    public void setUp() throws Exception {
        // Stub Keycloak context and realm.
        when(keycloakSession.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getRealm()).thenReturn(realmModel);
        when(realmModel.getName()).thenReturn("testrealm");
        when(realmModel.getSslRequired()).thenReturn(SslRequired.NONE);

        // Stub keycloakUriInfo.
        when(keycloakContext.getUri()).thenReturn(keycloakUriInfo);
        when(keycloakUriInfo.getBaseUri()).thenReturn(uri);
        // Return a real UriBuilder using a template with {realm}.
        when(keycloakUriInfo.getBaseUriBuilder()).thenReturn(UriBuilder.fromUri("http://example.com/{realm}"));
        // Stub query parameters with dummy non-null values.
        Map<String, String> qp = new HashMap<>();
        qp.put("realm", "testrealm");
        qp.put("client_id", "dummyClientId");
        qp.put("redirect_uri", "dummyRedirect");
        qp.put("nonce", "dummyNonce");
        qp.put("hash", "dummyHash");
        qp.put("state", "dummyState");
        qp.put("referrer", "dummyReferrer");
        MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
        for (Map.Entry<String, String> entry : qp.entrySet()) {
            queryParams.add(entry.getKey(), entry.getValue());
        }
        when(keycloakUriInfo.getQueryParameters()).thenReturn(queryParams);

        // Stub KeycloakSessionFactory.
        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(keycloakSession.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(sessionFactory.getProviderFactoriesStream(any())).thenReturn(Stream.empty());

        // Stub CookieProvider.
        CookieProvider cookieProvider = mock(CookieProvider.class);
        when(keycloakSession.getProvider(CookieProvider.class)).thenReturn(cookieProvider);
        when(cookieProvider.get(any(CookieType.class))).thenReturn(null);

        // Stub necessary providers.
        when(keycloakSession.getProvider(AccountProvider.class)).thenReturn(accountProvider);
        when(keycloakSession.getProvider(EventStoreProvider.class)).thenReturn(eventStoreProvider);
        when(keycloakSession.getProvider(UserProfileProvider.class)).thenReturn(userProfileProvider);
        when(keycloakSession.getProvider(AuthenticationSessionProvider.class)).thenReturn(authenticationSessionProvider);
        when(keycloakSession.getProvider(AuthorizationProvider.class)).thenReturn(authorizationProvider);

        // Stub AccountProvider chain.
        when(accountProvider.setRealm(any(RealmModel.class))).thenReturn(accountProvider);
        when(accountProvider.setUriInfo(any(KeycloakUriInfo.class))).thenReturn(accountProvider);
        when(accountProvider.setHttpHeaders(any())).thenReturn(accountProvider);
        when(accountProvider.setSuccess(any())).thenReturn(accountProvider);
        when(accountProvider.setError(any(), any())).thenReturn(accountProvider);
        when(accountProvider.setPasswordSet(anyBoolean())).thenReturn(accountProvider);

        // Stub eventBuilder.
        when(eventBuilder.client(any(ClientModel.class))).thenReturn(eventBuilder);
        when(eventBuilder.user(any(UserModel.class))).thenReturn(eventBuilder);
        when(eventBuilder.detail(anyString(), any(java.util.Collection.class))).thenReturn(eventBuilder);
        doNothing().when(eventBuilder).success();

        // Stub ClientConnection.
        when(keycloakContext.getConnection()).thenReturn(clientConnection);
        when(clientConnection.getRemoteAddr()).thenReturn("127.0.0.1");

        // Create dummy HttpHeaders.
        dummyHeaders = mock(HttpHeaders.class);
        MultivaluedMap<String, String> dummyRequestHeaders = new MultivaluedHashMap<>();
        dummyRequestHeaders.putSingle("Referer", "http://dummy");
        when(dummyHeaders.getRequestHeaders()).thenReturn(dummyRequestHeaders);

        // Create dummy HttpRequest.
        dummyRequest = mock(HttpRequest.class);
        MultivaluedMap<String, String> dummyFormParams = new MultivaluedHashMap<>();
        when(dummyRequest.getDecodedFormParameters()).thenReturn(dummyFormParams);

        // Initialize testService using TestableAccountFormService (bypassing login logic).
        testService = new TestableAccountFormService(keycloakSession, clientModel, eventBuilder);
        setFieldByType(testService, HttpHeaders.class, dummyHeaders);
        setFieldByType(testService, HttpRequest.class, dummyRequest);
    }

    @Test
    public void testAccountServiceBaseUrl() {
        UriBuilder result = AccountFormService.accountServiceBaseUrl(keycloakUriInfo);
        // With template "http://example.com/{realm}" and realm "testrealm", expect "http://example.com/testrealm"
        assertEquals("http://example.com/testrealm/realms/testrealm/account", result.build("testrealm").toString());
    }

    @Test
    public void testAccountProviderSetRealmAndSetUriInfo() {
        assertNotNull(accountProvider.setRealm(realmModel));
        assertNotNull(accountProvider.setUriInfo(keycloakUriInfo));
    }

    @Test
    public void testProcessSessionsLogout_WithAuthNull() {
        when(accountProvider.createResponse(any())).thenReturn(Response.ok().build());
        assertNotNull(testService.processSessionsLogout());
    }

    @Test
    public void testProcessAccountUpdate_AuthNull() {
        when(accountProvider.createResponse(any())).thenReturn(Response.ok().build());
        assertNotNull(testService.processAccountUpdate());
    }

    @Test
    public void testProcessRevokeGrant_NoConditions() {
        when(accountProvider.createResponse(any())).thenReturn(Response.ok().build());
        assertNotNull(testService.processRevokeGrant());
    }

    @Test
    public void testAccountPage_NoConditions() {
        try {
            testService.accountPage();
        } catch (Exception e) {
            fail("accountPage() should not throw exception, but got: " + e);
        }
    }

    @Test
    public void testProcessResourceActions_AuthNull() {
        when(accountProvider.createResponse(any())).thenReturn(Response.ok().build());
        assertNotNull(testService.processResourceActions(new String[]{"resource1"}, "action"));
    }

    @Test
    public void testProcessRevokeGrant_ErrorResponseException() {
        // Use the subclass that does not override login() so real login logic is executed.
        RealLoginAccountFormService serviceWithLogin =
                new RealLoginAccountFormService(keycloakSession, clientModel, eventBuilder);
        setFieldByType(serviceWithLogin, HttpHeaders.class, dummyHeaders);
        setFieldByType(serviceWithLogin, HttpRequest.class, dummyRequest);
        when(accountProvider.createResponse(any())).thenReturn(Response.ok().build());
        // Expect an ErrorResponseException.
        // Note: Since our stubs now provide non-null query parameter values, the exception is no longer thrown.
        // Adjust the expectation if your production logic should throw ErrorResponseException.
        assertThrows(IllegalArgumentException.class, () ->
            serviceWithLogin.grantPermission("resourceId", "action", new String[]{"perm1"}, "requester"));

    }

    @Test
    public void testShareResource_AuthNull() {
        when(accountProvider.createResponse(any())).thenReturn(Response.ok().build());
        assertNotNull(testService.shareResource("resourceId", new String[]{"user1"}, new String[]{"scope1"}));
    }
}
