package org.keycloak.services.resources.account;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.resteasy.core.ResteasyContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.common.Profile;
import org.keycloak.cookie.CookieProvider;
import org.keycloak.cookie.CookieType;
import org.keycloak.forms.account.AccountProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.services.managers.Auth;
import org.keycloak.services.messages.Messages;
import org.keycloak.userprofile.UserProfileProvider;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class AccountFormServiceTest1 {

    /**
     * RealAccountFormService uses the real CSRF check.
     */
    private static class RealAccountFormService extends AccountFormService {
        public RealAccountFormService(KeycloakSession session, ClientModel client, org.keycloak.events.EventBuilder eventBuilder) {
            super(session, client, eventBuilder);
        }
        @Override
        public void init() {
            super.init();
        }
        @Override
        protected Response login(String path) {
            return Response.ok().build();
        }
    }

    /**
     * TestableAccountFormService is used for most tests.
     */
    private static class TestableAccountFormService extends AccountFormService {
        public TestableAccountFormService(KeycloakSession session, ClientModel client, org.keycloak.events.EventBuilder eventBuilder) {
            super(session, client, eventBuilder);
        }
        @Override
        public void init() {
            super.init();
        }
        @Override
        protected Response login(String path) {
            return Response.ok().build();
        }
    }

    @Mock
    private KeycloakSession keycloakSession;
    @Mock
    private org.keycloak.models.KeycloakContext keycloakContext;
    @Mock
    private RealmModel realmModel;
    @Mock
    private ClientModel clientModel;
    @Mock
    private KeycloakUriInfo keycloakUriInfo;
    @Mock
    private AccountProvider accountProvider;
    @Mock
    private org.keycloak.events.EventBuilder eventBuilder;
    @Mock
    private HttpHeaders dummyHeaders;
    @Mock
    private CookieProvider cookieProvider;
    @Mock
    private UserProfileProvider userProfileProvider;
    @Mock
    private org.keycloak.events.EventStoreProvider eventStoreProvider;
    @Mock
    private UserSessionProvider userSessionProvider;
    @Mock
    private ClientConnection clientConnection;
    @Mock
    private AuthorizationProvider authorizationProvider;
    @Mock
    private HttpRequest dummyRequest;

    // Base URI for tests.
    private final URI baseUri = URI.create("http://example.com");

    private TestableAccountFormService testService;
    private RealAccountFormService realService;

    private Auth dummyAuth;
    @Mock
    private UserModel dummyUser;

    // Static mock for Profile
    private MockedStatic<Profile> profileMock;

    /**
     * Force-set a non-static, non-final field by its exact name.
     */
    private static void forceSetFieldByName(Object target, String fieldName, Object value) {
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            try {
                Field f = clazz.getDeclaredField(fieldName);
                if (Modifier.isStatic(f.getModifiers()) && Modifier.isFinal(f.getModifiers())) {
                    return;
                }
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException nsfe) {
                clazz = clazz.getSuperclass();
            } catch (Exception e) {
                throw new RuntimeException("Failed to force-set field " + fieldName + " in " + target.getClass().getName(), e);
            }
        }
        throw new RuntimeException("No field named '" + fieldName + "' found in class hierarchy of " + target.getClass().getName());
    }

    @BeforeEach
    public void setUp() throws Exception {
        // --- Static mocking for Profile ---
        profileMock = mockStatic(Profile.class);
        Profile dummyProfile = mock(Profile.class);
        when(dummyProfile.isFeatureEnabled(any(Profile.Feature.class))).thenReturn(true);
        profileMock.when(Profile::getInstance).thenReturn(dummyProfile);

        // --- Stub Keycloak context and related objects ---
        when(keycloakSession.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.getRealm()).thenReturn(realmModel);
        when(realmModel.getName()).thenReturn("testrealm");
        when(realmModel.getSslRequired()).thenReturn(SslRequired.NONE);
        when(keycloakContext.getUri()).thenReturn(keycloakUriInfo);
        when(keycloakUriInfo.getBaseUri()).thenReturn(baseUri);
        when(keycloakUriInfo.getBaseUriBuilder()).thenReturn(UriBuilder.fromUri("http://example.com/{realm}"));
        MultivaluedMap<String, String> defaultQueryParams = new MultivaluedHashMap<>();
        defaultQueryParams.add("realm", "testrealm");
        defaultQueryParams.add("client_id", "dummyClientId");
        defaultQueryParams.add("redirect_uri", "dummyRedirect");
        defaultQueryParams.add("nonce", "dummyNonce");
        defaultQueryParams.add("hash", "dummyHash");
        defaultQueryParams.add("referrer", "dummyReferrer");
        when(keycloakUriInfo.getQueryParameters()).thenReturn(defaultQueryParams);

        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(keycloakSession.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(sessionFactory.getProviderFactoriesStream(any())).thenReturn(Stream.empty());

        cookieProvider = mock(CookieProvider.class);
        when(keycloakSession.getProvider(CookieProvider.class)).thenReturn(cookieProvider);
        when(cookieProvider.get(any(CookieType.class))).thenReturn(null);

        when(keycloakSession.getProvider(AccountProvider.class)).thenReturn(accountProvider);
        when(keycloakSession.getProvider(org.keycloak.events.EventStoreProvider.class)).thenReturn(eventStoreProvider);
        when(keycloakSession.getProvider(UserProfileProvider.class)).thenReturn(userProfileProvider);
        when(keycloakSession.getProvider(UserSessionProvider.class)).thenReturn(userSessionProvider);
        when(keycloakSession.getProvider(AuthorizationProvider.class)).thenReturn(authorizationProvider);

        // Stub accountProvider chain methods.
        when(accountProvider.setRealm(any(RealmModel.class))).thenReturn(accountProvider);
        when(accountProvider.setUriInfo(any(KeycloakUriInfo.class))).thenReturn(accountProvider);
        when(accountProvider.setHttpHeaders(any(HttpHeaders.class))).thenReturn(accountProvider);
        when(accountProvider.setSuccess(any())).thenReturn(accountProvider);
        when(accountProvider.setError(any(), any())).thenReturn(accountProvider);
        when(accountProvider.setPasswordSet(anyBoolean())).thenReturn(accountProvider);
        when(accountProvider.createResponse(any())).thenReturn(Response.ok().build());

        when(eventBuilder.client(any(ClientModel.class))).thenReturn(eventBuilder);
        when(eventBuilder.user(any(UserModel.class))).thenReturn(eventBuilder);
        when(eventBuilder.detail(any(String.class), any(Collection.class))).thenReturn(eventBuilder);
        doNothing().when(eventBuilder).success();

        when(keycloakContext.getConnection()).thenReturn(clientConnection);
        when(clientConnection.getRemoteAddr()).thenReturn("127.0.0.1");

        MultivaluedMap<String, String> dummyFormParams = new MultivaluedHashMap<>();
        when(dummyRequest.getDecodedFormParameters()).thenReturn(dummyFormParams);
        when(dummyRequest.getHttpMethod()).thenReturn("GET");

        ResteasyContext.clearContextData();
        ResteasyContext.pushContext(HttpHeaders.class, dummyHeaders);
        ResteasyContext.pushContext(HttpRequest.class, dummyRequest);

        MultivaluedMap<String, String> dummyRequestHeaders = new MultivaluedHashMap<>();
        dummyRequestHeaders.putSingle("Origin", "http://example.com");
        dummyRequestHeaders.putSingle("Referer", "http://example.com");
        when(dummyHeaders.getRequestHeaders()).thenReturn(dummyRequestHeaders);

        // --- Additional stubbing for dependencies ---
        // Stub realm.getOTPPolicy() so that OTPCredentialModel.createFromPolicy doesn't fail.
        OTPPolicy dummyOTPPolicy = mock(OTPPolicy.class);
        when(realmModel.getOTPPolicy()).thenReturn(dummyOTPPolicy);
        // Stub dummyOTPPolicy.getType() to return a non-null string (if needed).
        when(dummyOTPPolicy.getType()).thenReturn("totp");

        // Stub dummyUser.credentialManager() for password updates.
        SubjectCredentialManager dummyCredMgr = mock(SubjectCredentialManager.class);
        when(dummyUser.credentialManager()).thenReturn(dummyCredMgr);
        when(dummyCredMgr.isConfiguredFor(PasswordCredentialModel.TYPE)).thenReturn(true);

        // Stub authorizationProvider's StoreFactory for shareResource.
        StoreFactory dummyStoreFactory = mock(StoreFactory.class);
        when(authorizationProvider.getStoreFactory()).thenReturn(dummyStoreFactory);
        PermissionTicketStore dummyTicketStore = mock(PermissionTicketStore.class);
        when(dummyStoreFactory.getPermissionTicketStore()).thenReturn(dummyTicketStore);

        // --- Instantiate service instances ---
        testService = new TestableAccountFormService(keycloakSession, clientModel, eventBuilder);
        realService = new RealAccountFormService(keycloakSession, clientModel, eventBuilder);

        when(keycloakSession.getAttribute("state_checker")).thenReturn("validState");

        // Force-inject instance fields using their actual names from AccountFormService.
        // Adjust the field names if they differ in your implementation.
        forceSetFieldByName(testService, "headers", dummyHeaders);
        forceSetFieldByName(testService, "request", dummyRequest);
        forceSetFieldByName(testService, "account", accountProvider);
        forceSetFieldByName(testService, "stateChecker", "validState");

        forceSetFieldByName(realService, "headers", dummyHeaders);
        forceSetFieldByName(realService, "request", dummyRequest);
        forceSetFieldByName(realService, "account", accountProvider);
        forceSetFieldByName(realService, "stateChecker", "validState");

        testService.init();
        realService.init();

        // Reset accountProvider to remove interactions performed during init().
        reset(accountProvider);

        dummyAuth = mock(Auth.class);
        when(dummyAuth.getUser()).thenReturn(dummyUser);
        doNothing().when(dummyAuth).require(any());

        ResteasyContext.clearContextData();
    }

    @AfterEach
    public void tearDown() {
        profileMock.close();
    }

    // @Test
    // public void testPasswordPage_WithAuth() {
    //     reset(accountProvider);
    //     // Inject dummyAuth
    //     forceSetFieldByName(testService, "auth", dummyAuth);
    //     SubjectCredentialManager credManager = mock(SubjectCredentialManager.class);
    //     when(dummyUser.credentialManager()).thenReturn(credManager);
    //     when(credManager.isConfiguredFor(PasswordCredentialModel.TYPE)).thenReturn(true);
    //     MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
    //     formParams.add("stateChecker", "validState");
    //     when(dummyRequest.getDecodedFormParameters()).thenReturn(formParams);
    //     Response response = testService.passwordPage();
    //     verify(accountProvider).setPasswordSet(true);
    //     assertNotNull(response);
    // }

    // @Test
    // public void testProcessTotpUpdate_InvalidChallenge() {
    //     reset(accountProvider);
    //     forceSetFieldByName(testService, "auth", dummyAuth);
    //     MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
    //     formParams.add("submitAction", "Update");
    //     formParams.add("totp", ""); // blank totp
    //     formParams.add("stateChecker", "validState");
    //     when(dummyRequest.getDecodedFormParameters()).thenReturn(formParams);
    //     Response response = testService.processTotpUpdate();
    //     verify(accountProvider).setError(Response.Status.FORBIDDEN, Messages.MISSING_TOTP);
    //     assertNotNull(response);
    // }

    // @Test
    // public void testProcessPasswordUpdate_MissingPasswordNew() {
    //     reset(accountProvider);
    //     forceSetFieldByName(testService, "auth", dummyAuth);
    //     MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
    //     formParams.add("password", "oldpass");
    //     formParams.add("password-confirm", "newpass");
    //     formParams.add("stateChecker", "validState");
    //     when(dummyRequest.getDecodedFormParameters()).thenReturn(formParams);
    //     Response response = testService.processPasswordUpdate();
    //     verify(accountProvider).setError(Response.Status.FORBIDDEN, Messages.MISSING_PASSWORD);
    //     assertNotNull(response);
    // }

    // @Test
    // public void testProcessFederatedIdentityUpdate_MissingProvider() {
    //     reset(accountProvider);
    //     forceSetFieldByName(testService, "auth", dummyAuth);
    //     MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
    //     formParams.add("action", "add");
    //     formParams.add("stateChecker", "validState");
    //     when(dummyRequest.getDecodedFormParameters()).thenReturn(formParams);
    //     Response response = testService.processFederatedIdentityUpdate();
    //     verify(accountProvider).setError(Response.Status.FORBIDDEN, Messages.MISSING_IDENTITY_PROVIDER);
    //     assertNotNull(response);
    // }

    // @Test
    // public void testShareResource_MissingUserIds() {
    //     reset(accountProvider);
    //     forceSetFieldByName(testService, "auth", dummyAuth);
    //     MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
    //     formParams.add("stateChecker", "validState");
    //     when(dummyRequest.getDecodedFormParameters()).thenReturn(formParams);
    //     Response response = testService.shareResource("dummyResource", null, new String[]{"scope1"});
    //     verify(accountProvider).setError(Response.Status.FORBIDDEN, Messages.MISSING_PASSWORD);
    //     assertNotNull(response);
    // }


      @Test
      public void testSessionsPage_WithAuth() {
          when(keycloakSession.getProvider(UserSessionProvider.class)).thenReturn(userSessionProvider);
          Response response = testService.sessionsPage();
          assertNotNull(response);
      }

    @Test
    public void testAccountServiceBaseUrl() {
        UriBuilder result = AccountFormService.accountServiceBaseUrl(keycloakUriInfo);
        String builtUrl = result.build("testrealm").toString();
        assertTrue(builtUrl.contains("account"));
    }

    @Test
    public void testTotpPage_WithMode() {
        MultivaluedMap<String, String> qp = new MultivaluedHashMap<>();
        qp.add("mode", "testmode");
        qp.add("stateChecker", "validState");
        when(keycloakUriInfo.getQueryParameters()).thenReturn(qp);
        Response response = testService.totpPage();
        verify(accountProvider).setAttribute("mode", "testmode");
        assertNotNull(response);
    }

    @Test
    public void testFederatedIdentityPage_WithAuth() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.add("stateChecker", "validState");
        when(dummyRequest.getDecodedFormParameters()).thenReturn(formParams);
        Response response = testService.federatedIdentityPage();
        assertNotNull(response);
    }

    @Test
    public void testLogPage_EventsDisabled() {
        when(realmModel.isEventsEnabled()).thenReturn(false);
        assertThrows(NotFoundException.class, () -> testService.logPage());
    }

    @Test
    public void testLogPage_EventsEnabled() {
        when(realmModel.isEventsEnabled()).thenReturn(true);
        when(accountProvider.createResponse(any())).thenReturn(Response.ok().build());
        Response response = testService.logPage();
        assertNotNull(response);
    }

    @Test
    public void testApplicationsPage() {
        Response response = testService.applicationsPage();
        assertNotNull(response);
    }

    @Test
    public void testProcessTotpUpdate_Cancel() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.add("submitAction", "Cancel");
        formParams.add("stateChecker", "validState");
        when(dummyRequest.getDecodedFormParameters()).thenReturn(formParams);
        Response response = testService.processTotpUpdate();
        assertNotNull(response);
    }

    @Test
    public void testResourcesPage() {
        Response response = testService.resourcesPage("dummyResource");
        assertNotNull(response);
    }

    @Test
    public void testResourceDetailPage() {
        Response response = testService.resourceDetailPage("dummyResource");
        assertNotNull(response);
    }

    @Test
    public void testResourceDetailPageAfterGrant() {
        Response response = testService.resourceDetailPageAfterGrant("dummyResource");
        assertNotNull(response);
    }

    @Test
    public void testGrantPermission_InvalidResource() {
        reset(accountProvider);
        forceSetFieldByName(testService, "auth", dummyAuth);
        ResourceStore resourceStore = mock(ResourceStore.class);
        StoreFactory storeFactory = mock(StoreFactory.class);
        when(authorizationProvider.getStoreFactory()).thenReturn(storeFactory);
        when(storeFactory.getResourceStore()).thenReturn(resourceStore);
        when(resourceStore.findById(any(), eq("nonexistent"))).thenReturn(null);
        assertThrows(WebApplicationException.class, () ->
            testService.grantPermission("nonexistent", "grant", new String[]{"perm1"}, "requester"));
    }

    @Test
    public void testResourceDetailPageAfterShare() {
        Response response = testService.resourceDetailPageAfterShare("dummyResource");
        assertNotNull(response);
    }

    @Test
    public void testProcessResourceActions() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.add("stateChecker", "validState");
        when(dummyRequest.getDecodedFormParameters()).thenReturn(formParams);
        Response response = testService.processResourceActions(new String[]{"res1"}, "cancel");
        assertNotNull(response);
    }

    @Test
    public void testLoginRedirectUrl() {
        UriBuilder builder = AccountFormService.loginRedirectUrl(keycloakUriInfo.getBaseUriBuilder());
        String url = builder.build("testrealm").toString();
        assertFalse(url.isEmpty(), "Login redirect URL should not be empty");
    }

    @Test
    public void testGetBaseRedirectUri() {
        URI redirectUri = testService.getBaseRedirectUri();
        assertTrue(redirectUri.toString().contains("account"));
    }

    @Test
    public void testIsPasswordSet() {
        UserModel user = mock(UserModel.class);
        SubjectCredentialManager credManager = mock(SubjectCredentialManager.class);
        when(user.credentialManager()).thenReturn(credManager);
        when(credManager.isConfiguredFor(PasswordCredentialModel.TYPE)).thenReturn(true);
        assertTrue(AccountFormService.isPasswordSet(user));
    }
}