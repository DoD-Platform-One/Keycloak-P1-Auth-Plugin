package org.keycloak.services.resources.account;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.*;
import jdk.jfr.consumer.EventStream;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.*;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.Profile;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.common.util.KerberosJdkProvider;
import org.keycloak.common.util.UriUtils;
import org.keycloak.credential.CredentialInput;
import org.keycloak.events.*;
import org.keycloak.forms.account.AccountProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.locale.LocaleSelectorProvider;
import org.keycloak.locale.LocaleUpdaterProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.OTPCredentialData;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.AccountUrls;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.urls.UrlType;
import org.keycloak.userprofile.AttributeChangeListener;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.userprofile.ValidationException;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.CredentialHelper;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.powermock.api.mockito.PowerMockito.*;


@RunWith(PowerMockRunner.class)
@PrepareForTest({
        KerberosJdkProvider.class, Profile.class, Profile.Feature.Type.class,
        UriBuilder.class, OIDCLoginProtocolService.class, AppAuthManager.class,
        AuthenticationManager.AuthResult.class, AuthenticationManager.class,
        DefaultClientSessionContext.class, EventBuilder.class, AuthorizationProvider.class,
        UserProfileProvider.class, UserProfile.class, UriUtils.class, JsonSerialization.class,
        RedirectUtils.class, Validation.class, AccountUrls.class, Urls.class, OTPCredentialModel.class,
        CredentialValidation.class, CredentialHelper.class, ValidationException.class,
})
public class AccountFormServiceTest {

    @Mock private KeycloakSession keycloakSession;
    @Mock private ClientModel clientModel;
    @Mock private EventBuilder eventBuilder;
    @Mock private RealmModel realmModel;
    @Mock private UserModel userModel;
    @Mock private UriInfo uriInfo;
    @Mock private UriBuilder baseUriBuilder;
    @Mock private UserProfileProvider userProfileProvider;
    @Mock private AuthorizationProvider authorizationProvider;
    @Mock private HttpHeaders httpHeaders;
    @Mock private HttpRequest httpRequest;
    @Mock private KeycloakUriInfo keycloakUriInfo;
    @Mock private AuthenticationManager.AuthResult authResult;
    @Mock private AppAuthManager appAuthManager;
    @Mock private UserProfile userProfile;
    @Mock private AccountProvider accountProvider;
    @Mock private UserSessionModel userSessionModel;
    @Mock private PermissionTicketStore permissionTicketStore;
    @Mock private OTPCredentialModel otpCredentialModel;

    // local variables
    private final String resourceId = "resourceId";
    private final String action = "action";
    private final String[] permissionId = {"permission1", "permission2", "permission3"};
    private final String requester = "requester";
    private final String[] userIds = {"user1", "user2", "user3"};
    private final String[] scopes = {"scope1", "scope2", "scope3"};
    private final String[] resourceIds = {"resourceId1", "resourceId2", "resourceId3"};
    private final URI uri = URI.create("http://example.com");

    private AccountFormService accountFormService;

    @Before
    public void setUp() throws Exception {

        // local variables
        String get = "GET";
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();

        // Add some sample values
        multivaluedMap.add("stateChecker", "value1");

        // mock static classes
        mockStatic(Profile.Feature.Type.class);
        mockStatic(Profile.class);
        mockStatic(KerberosJdkProvider.class);
        mockStatic(UriBuilder.class);
        mockStatic(OIDCLoginProtocolService.class);
        mockStatic(AppAuthManager.class);
        mockStatic(AuthenticationManager.class);
        mockStatic(AuthenticationManager.AuthResult.class);
        mockStatic(DefaultClientSessionContext.class);
        mockStatic(UriUtils.class);
        mockStatic(JsonSerialization.class);
        mockStatic(RedirectUtils.class);
        mockStatic(OTPCredentialModel.class);
        mockStatic(CredentialValidation.class);
        mockStatic(CredentialHelper.class);

        // mocks
        KeycloakContext keycloakContext = mock(KeycloakContext.class);
        EventStoreProvider eventStoreProvider = mock(EventStoreProvider.class);
        KerberosJdkProvider kerberosJdkProvider = mock(KerberosJdkProvider.class);
        ClientConnection clientConnection = mock(ClientConnection.class);
        LoginFormsProvider loginFormsProvider = mock(LoginFormsProvider.class);
        EventQuery eventQuery = mock(EventQuery.class);
        OTPPolicy otpPolicy = mock(OTPPolicy.class);
        StoreFactory storeFactory = mock(StoreFactory.class);
        ResourceStore resourceStore = mock(ResourceStore.class);
        UserSessionProvider userSessionProvider = mock(UserSessionProvider.class);
        DefaultClientSessionContext defaultClientSessionContext = mock(DefaultClientSessionContext.class);
        AccessToken accessToken = mock(AccessToken.class);
        TokenManager tokenManager = mock(TokenManager.class);
        UserProvider userProvider = mock(UserProvider.class);
        PermissionTicket permissionTicket = mock(PermissionTicket.class);
        ScopeStore scopeStore = mock(ScopeStore.class);
        Resource resource = mock(Resource.class);
        AuthenticationSessionProvider authenticationSessionProvider = mock(AuthenticationSessionProvider.class);
        LocaleUpdaterProvider localeUpdaterProvider = mock(LocaleUpdaterProvider.class);
        RootAuthenticationSessionModel rootAuthenticationSessionModel = mock(RootAuthenticationSessionModel.class);
        OTPCredentialData otpCredentialData = mock(OTPCredentialData.class);
        Event event1 = mock(Event.class);
        Event event2 = mock(Event.class);

        // keycloakSession
        when(keycloakSession.getContext()).thenReturn(keycloakContext);
        when(keycloakSession.getContext().getUri()).thenReturn(keycloakUriInfo);
        when(keycloakSession.getContext().getConnection()).thenReturn(clientConnection);
        when(keycloakSession.getContext().getUri().getQueryParameters()).thenReturn(multivaluedMap);
        when(keycloakSession.getProvider(eq(EventStoreProvider.class))).thenReturn(eventStoreProvider);
        when(keycloakSession.getProvider(eq(AccountProvider.class))).thenReturn(accountProvider);
        when(keycloakSession.getProvider(eq(LoginFormsProvider.class))).thenReturn(loginFormsProvider);
        when(keycloakSession.getProvider(eq(UserProfileProvider.class))).thenReturn(userProfileProvider);
        when(keycloakSession.getProvider(eq(AuthorizationProvider.class))).thenReturn(authorizationProvider);
        when(keycloakSession.getProvider(eq(LocaleUpdaterProvider.class))).thenReturn(localeUpdaterProvider);
        when(keycloakSession.getAttribute("state_checker")).thenReturn("value1");
        when(keycloakSession.sessions()).thenReturn(userSessionProvider);
        when(keycloakSession.tokens()).thenReturn(tokenManager);
        when(keycloakSession.users()).thenReturn(userProvider);
        when(keycloakSession.users().getUserByUsername(eq(realmModel), anyString())).thenReturn(userModel);
        when(keycloakSession.authenticationSessions()).thenReturn(authenticationSessionProvider);
        when(keycloakSession.authenticationSessions().getRootAuthenticationSession(any(), any())).thenReturn(rootAuthenticationSessionModel);

        // storeFactory
        when(storeFactory.getResourceStore()).thenReturn(resourceStore);

        // authorizationProvider
        when(authorizationProvider.getStoreFactory()).thenReturn(storeFactory);
        when(authorizationProvider.getStoreFactory().getPermissionTicketStore()).thenReturn(permissionTicketStore);
        when(authorizationProvider.getStoreFactory().getScopeStore()).thenReturn(scopeStore);
        when(authorizationProvider.getStoreFactory().getResourceStore().findById(eq(realmModel), eq(null), eq(resourceId))).thenReturn(resource);

        // loginFormsProvider
        when(loginFormsProvider.setError(anyString(), any())).thenReturn(loginFormsProvider);

        // EventStoreProvider
        when(eventStoreProvider.createQuery()).thenReturn(eventQuery);

        // EventQuery
        when(eventQuery.type(any())).thenReturn(eventQuery);
        when(eventQuery.realm(any())).thenReturn(eventQuery);
        when(eventQuery.user(any())).thenReturn(eventQuery);
        when(eventQuery.maxResults(anyInt())).thenReturn(eventQuery);
        when(eventQuery.getResultStream()).thenReturn(Stream.of(event1, event2));

        // Event
        // testLogPage - line 510 from AccountFormService require more data for testing
        when(event1.getDetails()).thenReturn(null);
        when(event2.getDetails()).thenReturn(null);

        // keycloakContext
        when(keycloakContext.getUri()).thenReturn(keycloakUriInfo);
        when(keycloakContext.getRealm()).thenReturn(realmModel);
        when(keycloakContext.getRequestHeaders()).thenReturn(httpHeaders);
        when(keycloakContext.getHttpRequest()).thenReturn(httpRequest);

        // keycloakUriInfo
        when(keycloakUriInfo.getBaseUri()).thenReturn(uri);

        // accountProvider
        when(accountProvider.setRealm(realmModel)).thenReturn(accountProvider);
        when(accountProvider.setUriInfo(keycloakUriInfo)).thenReturn(accountProvider);
        when(accountProvider.setHttpHeaders(httpHeaders)).thenReturn(accountProvider);
        when(accountProvider.setFeatures(anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean())).thenReturn(accountProvider);
        when(accountProvider.setSuccess(any())).thenReturn(accountProvider);
        when(accountProvider.setError(any(), any())).thenReturn(accountProvider);
        when(accountProvider.setPasswordSet(anyBoolean())).thenReturn(accountProvider);

        // httpHeaders
        when(httpHeaders.getRequestHeaders()).thenReturn(multivaluedMap);

        // httpRequest
        when(httpRequest.getHttpMethod()).thenReturn(get);
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);

        // realmModel
        when(realmModel.isIdentityFederationEnabled()).thenReturn(true);
        when(realmModel.isEventsEnabled()).thenReturn(true);
        when(realmModel.getName()).thenReturn("realm");
        when(realmModel.getSslRequired()).thenReturn(SslRequired.ALL);
        when(realmModel.getOTPPolicy()).thenReturn(otpPolicy);

        // ClientConnection
        when(clientConnection.getRemoteAddr()).thenReturn("127.0.0.1");

        // kerberos
        when(KerberosJdkProvider.getProvider()).thenReturn(kerberosJdkProvider);

        // Profile
        when(Profile.isFeatureEnabled(eq(Profile.Feature.AUTHORIZATION))).thenReturn(true);

        // uriInfo
        when(uriInfo.getBaseUriBuilder()).thenReturn(baseUriBuilder);

        // baseUriBuilder
        when(baseUriBuilder.path(any(Class.class))).thenReturn(baseUriBuilder);
        when(baseUriBuilder.path(any(Class.class), any(String.class))).thenReturn(baseUriBuilder);
        when(baseUriBuilder.path(any(String.class))).thenReturn(baseUriBuilder);
        when(baseUriBuilder.build(any())).thenReturn(uri);
        when(baseUriBuilder.queryParam(anyString(), any())).thenReturn(baseUriBuilder);
        when(UriBuilder.fromUri(any(URI.class))).thenReturn(baseUriBuilder);
        when(UriBuilder.fromUri(anyString())).thenReturn(baseUriBuilder);

        // RealmsResource
        when(RealmsResource.accountUrl(baseUriBuilder)).thenReturn(baseUriBuilder);

        // userModel
        when(userModel.credentialManager()).thenReturn(mock(SubjectCredentialManager.class));
        when(userModel.credentialManager().isConfiguredFor(eq(PasswordCredentialModel.TYPE))).thenReturn(true);
        when(userModel.hasRole(any())).thenReturn(true);

        // OIDCLoginProtocolService
        when(OIDCLoginProtocolService.authUrl(any(UriInfo.class))).thenReturn(baseUriBuilder);

        // AppAuthManager
        whenNew(AppAuthManager.class).withNoArguments().thenReturn(appAuthManager);
        when(appAuthManager.authenticateIdentityCookie(keycloakSession, realmModel)).thenReturn(authResult);

        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(authResult);

        // AuthResult
        when(authResult.getSession()).thenReturn(userSessionModel);
        when(authResult.getToken()).thenReturn(accessToken);
        when(authResult.getUser()).thenReturn(userModel);

        // userSessionModel
        when(userSessionModel.getUser()).thenReturn(userModel);

        // permissionTicketStore
        when(permissionTicketStore.create(any(), any(), any(), any())).thenReturn(permissionTicket);

        // DefaultClientSessionContext
        when(DefaultClientSessionContext.fromClientSessionScopeParameter(any(), any())).thenReturn(defaultClientSessionContext);

        // eventBuilder
        when(eventBuilder.clone()).thenReturn(eventBuilder);
        when(eventBuilder.event(any(EventType.class))).thenReturn(eventBuilder);
        when(eventBuilder.client(any(ClientModel.class))).thenReturn(eventBuilder);
        when(eventBuilder.user(any(UserModel.class))).thenReturn(eventBuilder);
        when(eventBuilder.detail(anyString(), anyString())).thenReturn(eventBuilder);
        when(eventBuilder.detail(anyString(), any(Collection.class))).thenReturn(eventBuilder);
        when(eventBuilder.detail(anyString(), any(Stream.class))).thenReturn(eventBuilder);

        // userProfileProvider
        when(userProfileProvider.create(any(), any(), any())).thenReturn(userProfile);

        // OTPCredentialModel
        when(OTPCredentialModel.createFromPolicy(any(), any(), any())).thenReturn(otpCredentialModel);
        when(otpCredentialModel.getOTPCredentialData()).thenReturn(otpCredentialData);
        when(otpCredentialModel.getDecodedSecret()).thenReturn("someData".getBytes(StandardCharsets.UTF_8));

        // otpCredentialData
        when(otpCredentialData.getSubType()).thenReturn("totp");
        when(otpCredentialData.getAlgorithm()).thenReturn("some algo");
        when(otpCredentialData.getDigits()).thenReturn(3);
        when(otpCredentialData.getPeriod()).thenReturn(5);

        // CredentialValidation
        when(CredentialValidation.validOTP(anyString(), any(), anyInt())).thenReturn(false);

        // CredentialHelper
        when(CredentialHelper.createOTPCredential(any(), any(), any(), anyString(), any())).thenReturn(false);
    }

    @Test
    public void testAccountServiceBaseUrl(){
        // accountServiceBaseUrl test
        assertEquals(baseUriBuilder, AccountFormService.accountServiceBaseUrl(uriInfo));
    }

    @Test
    public void testAccountServiceApplicationPage(){
        // accountServiceApplicationPage test
        assertEquals(baseUriBuilder, AccountFormService.accountServiceApplicationPage(uriInfo));
    }

    @Test
    public void testTotpUrl(){
        // totpUrl test
        assertEquals(baseUriBuilder, AccountFormService.totpUrl(baseUriBuilder));
    }

    @Test
    public void testPasswordUrl(){
        // passwordUrl test
        assertEquals(baseUriBuilder, AccountFormService.passwordUrl(baseUriBuilder));
    }

    @Test
    public void testLoginRedirectUrl(){
        // loginRedirectUrl test
        assertEquals(baseUriBuilder, AccountFormService.loginRedirectUrl(baseUriBuilder));
    }
    @Test
    public void testIsPasswordSet(){
        // isPasswordSet test
        assertTrue(AccountFormService.isPasswordSet(userModel));
    }

    @Test
    public void testGetValidPaths(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // getValidPaths test
        assertEquals(12, accountFormService.getValidPaths().size());
    }

    @Test
    public void testAccountPage() throws IOException {
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // accountPage test
        assertNull(accountFormService.accountPage());

        // Condition 2 - tabId not null
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add(org.keycloak.models.Constants.TAB_ID, "some value");
        multivaluedMap.add(LocaleSelectorProvider.KC_LOCALE_PARAM, "some value");
        // conditions
        when(keycloakSession.getContext().getUri().getQueryParameters()).thenReturn(multivaluedMap);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // accountPage test
        assertNull(accountFormService.accountPage());

        // Condition 3 - authSession not null
        // mocks
        AuthenticationSessionModel authenticationSessionModel = mock(AuthenticationSessionModel.class);
        // authSession not null
        when(keycloakSession.authenticationSessions().getRootAuthenticationSession(any(), any()).getAuthenticationSession(any(), any())).thenReturn(authenticationSessionModel);
        // accountPage test
        assertNull(accountFormService.accountPage());

        // Condition 4 - forwardedError not null
        // mocks
        FormMessage formMessage = mock(FormMessage.class);
        // forwardedError not null
        when(authenticationSessionModel.getAuthNote(anyString())).thenReturn("error");
        when(JsonSerialization.readValue(eq("error"), eq(FormMessage.class))).thenReturn(formMessage);
        // accountPage test
        assertNull(accountFormService.accountPage());

        // Condition 5 - Test private forwardToPage - force ForbiddenException
        // conditions
        when(userModel.hasRole(any())).thenReturn(false);
        // constructor
        AccountFormService accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // accountPage test
        assertNull(accountFormService.accountPage());

    }

    @Test
    public void privateGetReferrerFromAccountPage(){
        // Condition 1
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("referrer", "some value");
        // conditions
        when(keycloakSession.getContext().getUri().getQueryParameters()).thenReturn(multivaluedMap);
        when(keycloakSession.getContext().getUri(any(UrlType.class))).thenReturn(keycloakUriInfo);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        //accountPage test
        assertNull(accountFormService.accountPage());

        // Condition 2
        // referrerClient not null
        when(realmModel.getClientByClientId(anyString())).thenReturn(clientModel);
        assertNull(accountFormService.accountPage());

        // Condition 3
        // referrerUri not null but referrerClient is null
        multivaluedMap.add("referrer_uri", "some value");
        when(realmModel.getClientByClientId(anyString())).thenReturn(null);
        assertNull(accountFormService.accountPage());

        // Condition 4
        // referrerUri not null condition continuation
        when(RedirectUtils.verifyRedirectUri(any(), any(), any())).thenReturn("redirecion success");
        assertNull(accountFormService.accountPage());

        // Condition 5
        // referrerUri not null and referrerClient not null
        when(realmModel.getClientByClientId(anyString())).thenReturn(clientModel);
        assertNull(accountFormService.accountPage());

//        // Condition 6 - client = null
//        // client is null (not working and I want to punch the computer)
//        // constructor
//        accountFormService = new AccountFormService(keycloakSession, null, eventBuilder);
//        assertNull(accountFormService.accountPage());

//        // Condition 7 - referrerName have value
//        // constructor
//        when(clientModel.getName()).thenReturn(null);
//        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
//        assertNull(accountFormService.accountPage());
    }

    @Test (expected = RuntimeException.class)
    public void privateForwardToPageRuntimeException() throws IOException {
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();

        // Add some sample values
        multivaluedMap.add(org.keycloak.models.Constants.TAB_ID, "some value");
        multivaluedMap.add(LocaleSelectorProvider.KC_LOCALE_PARAM, "some value");

        // mocks
        AuthenticationSessionModel authenticationSessionModel = mock(AuthenticationSessionModel.class);
        FormMessage formMessage = mock(FormMessage.class);

        // conditions
        when(authenticationSessionModel.getAuthNote(anyString())).thenReturn("error");
        when(JsonSerialization.readValue(eq("error"), eq(FormMessage.class))).thenReturn(formMessage);
        when(keycloakSession.authenticationSessions().getRootAuthenticationSession(any(), any()).getAuthenticationSession(any(), any())).thenReturn(authenticationSessionModel);
        when(keycloakSession.getContext().getUri().getQueryParameters()).thenReturn(multivaluedMap);

        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // forwardedError RunTimeException
        when(JsonSerialization.readValue(eq("error"), eq(FormMessage.class))).thenThrow(IOException.class);

        // accountPage test
        assertNull(accountFormService.accountPage());
    }

    @Test
    public void testTotpPage(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // totpPage test
        assertNull(accountFormService.totpPage());
    }

    @Test
    public void testPasswordPage(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // totpPage test
        assertNull(accountFormService.passwordPage());

        // Condition 2 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // totpPage test
        assertNotNull(accountFormService.passwordPage());
    }

    @Test
    public void testFederatedIdentityPage(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // totpPage test
        assertNull(accountFormService.federatedIdentityPage());
    }

    @Test
    public void testLogPage(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // logPage test
        assertNull(accountFormService.logPage());

        // Condition 2 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // totpPage test
        assertNotNull(accountFormService.logPage());
    }

    @Test (expected = NotFoundException.class)
    public void logPageNotFoundException(){
        // force the exception
        when(realmModel.isEventsEnabled()).thenReturn(false);
        // constructor
        AccountFormService accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // logPage
        accountFormService.logPage();
    }

    @Test
    public void testSessionsPage(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // sessionsPage test
        assertNull(accountFormService.sessionsPage());

        // Condition 2 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // sessionsPage test
        assertNotNull(accountFormService.sessionsPage());
    }

    @Test
    public void testApplicationsPage(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // applicationsPage test
        assertNull(accountFormService.applicationsPage());
    }

    @Test
    public void testProcessAccountUpdate(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processAccountUpdate test
        assertNull(accountFormService.processAccountUpdate());

        // Condition 2 - ValidationException (empty error)
        ValidationException validationException = mock(ValidationException.class);
        // throwException
        doThrow(validationException).when(userProfile).update(anyBoolean(), any(AttributeChangeListener.class));
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        //processAccountUpdate test
        assertNull(accountFormService.processAccountUpdate());

        // Condition 3 - ValidationException (error with value)
        mockStatic(Validation.class);
        // variables
        List<FormMessage> formMessageList = mock(ArrayList.class);
        Response response = mock(Response.class);
        // conditions
        when(Validation.getFormErrorsFromValidation(any())).thenReturn(formMessageList);
        when(formMessageList.isEmpty()).thenReturn(false);
        when(accountProvider.setErrors(any(), any())).thenReturn(accountProvider);
        when(accountProvider.setProfileFormData(any())).thenReturn(accountProvider);
        when(accountProvider.createResponse(any())).thenReturn(response);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processAccountUpdate test
        assertEquals(response, accountFormService.processAccountUpdate());

        // Condition 4 - ValidationException (error with value) - EMAIL_EXISTS and USERNAME_EXISTS
        // conditions
        when(validationException.hasError(Messages.EMAIL_EXISTS, Messages.USERNAME_EXISTS)).thenReturn(true);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processAccountUpdate test
        assertEquals(response, accountFormService.processAccountUpdate());

        // Condition 5 - ValidationException (error with value) - READ_ONLY_USERNAME
        // conditions
        when(validationException.hasError(Messages.READ_ONLY_USERNAME)).thenReturn(true);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processAccountUpdate test
        assertEquals(response, accountFormService.processAccountUpdate());

        // Condition 6 - ReadOnlyException
        // throwException
        doThrow(new ReadOnlyException()).when(userProfile).update(anyBoolean(), any(AttributeChangeListener.class));
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processAccountUpdate test
        assertEquals(response, accountFormService.processAccountUpdate());

        // Condition 7 - Action = Cancel
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("submitAction", "Cancel");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        //processAccountUpdate test
        assertNotNull(accountFormService.processAccountUpdate());

        // Condition 8 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processAccountUpdate test
        assertNotNull(accountFormService.processAccountUpdate());
    }

    @Test (expected = ForbiddenException.class)
    public void processAccountUpdateForbiddenException(){
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("submitAction", "some value");
        multivaluedMap.add("stateChecker", "some value");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        // constructor
        AccountFormService accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        //processAccountUpdate test
        assertNull(accountFormService.processAccountUpdate());
    }

    @Test
    public void testProcessSessionsLogout(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processSessionsLogout test
        assertNotNull(accountFormService.processSessionsLogout());

        // Condition 2 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processSessionsLogout test
        assertNotNull(accountFormService.processSessionsLogout());
    }

    @Test
    public void testProcessRevokeGrant(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processRevokeGrant test
        assertNull(accountFormService.processRevokeGrant());

        // Condition 2 - clientid not null
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("clientId", "value1");
        multivaluedMap.add("stateChecker", "value1");
        multivaluedMap.add("referrer", "some value");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        when(realmModel.getClientById(anyString())).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processRevokeGrant test
        assertNull(accountFormService.processRevokeGrant());

        // Condition 3 - client not null
        when(realmModel.getClientById(anyString())).thenReturn(clientModel);
        when(clientModel.getClientId()).thenReturn("something");
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processRevokeGrant test
        assertNotNull(accountFormService.processRevokeGrant());

        // condition 4 - referrer not null
        when(keycloakSession.getContext().getUri().getQueryParameters()).thenReturn(multivaluedMap);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processRevokeGrant test
        assertNotNull(accountFormService.processRevokeGrant());

        // Condition 5 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processRevokeGrant test
        assertNotNull(accountFormService.processRevokeGrant());
    }

    @Test
    public void testProcessTotpUpdate(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processTotpUpdate test
        assertNull(accountFormService.processTotpUpdate());

        // Condition 2
//        // FORBIDDEN EXCEPTION
//        // Condition 3 - Action = Delete
//        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
//
//        // Add some sample values
//        multivaluedMap.add("submitAction", "Delete");
//
//        // conditions
//        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
//
//        // constructor
//        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
//
//        //processTotpUpdate test
//        assertNull(accountFormService.processTotpUpdate());

        // Condition 3 - totp validOTP CredentialHelper = false
        multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("stateChecker", "value1");
        multivaluedMap.add("totp", "value2");
        multivaluedMap.add("totpSecret", "value3");
        multivaluedMap.add("userLabel", "value4");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        when(CredentialValidation.validOTP(anyString(), any(), anyInt())).thenReturn(true);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        //processTotpUpdate test
        assertNull(accountFormService.processTotpUpdate());

        // Condition 4 - totp validOTP CredentialHelper = true
        // conditions
        when(CredentialHelper.createOTPCredential(any(), any(), any(), anyString(), any())).thenReturn(true);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        //processTotpUpdate test
        assertNull(accountFormService.processTotpUpdate());

        // Condition 5 - totp not validOTP
        // conditions
        when(CredentialValidation.validOTP(anyString(), any(), anyInt())).thenReturn(false);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        //processTotpUpdate test
        assertNull(accountFormService.processTotpUpdate());

        // Condition 6 - Action = Cancel
        // variables
        multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("submitAction", "Cancel");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        //processTotpUpdate test
        assertNull(accountFormService.processTotpUpdate());

        // Condition 7 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processTotpUpdate test
        assertNotNull(accountFormService.processTotpUpdate());
    }

    @Test
//    @Test (expected = ForbiddenException.class) // This is a lie, please remove
    public void testProcessPasswordUpdate(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processPasswordUpdate
        assertNull(accountFormService.processPasswordUpdate());

        // Condition 2 - formData contains password
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("stateChecker", "value1");
        multivaluedMap.add("password", "somePassword");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processPasswordUpdate
        assertNull(accountFormService.processPasswordUpdate());

        // Condition 3 - user.credentialManagaer is not valid
        // conditions
        when(userModel.credentialManager().isValid(any(CredentialInput.class))).thenReturn(true);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processPasswordUpdate
        assertNull(accountFormService.processPasswordUpdate());

        // Condition 4 - password-new populated
        // Add some sample values
        multivaluedMap.add("password-new", "somePassword");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        when(userModel.credentialManager().isConfiguredFor(PasswordCredentialModel.TYPE)).thenReturn(false);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processPasswordUpdate
        assertNull(accountFormService.processPasswordUpdate());

        // Condition 5 - password-confirm populated
        // Add some sample values
        multivaluedMap.add("password-confirm", "somePassword");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processPasswordUpdate
        assertNull(accountFormService.processPasswordUpdate());

        // Condition 6

        // Condition 7

        // Condition 8

        // Condition 9 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processPasswordUpdate test
        assertNotNull(accountFormService.processPasswordUpdate());
    }

    @Test
    public void testProcessFederatedIdentityUpdate(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNull(accountFormService.processFederatedIdentityUpdate());

        // Condition 2 - validation is not empty
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("providerId", "value1");
        multivaluedMap.add("stateChecker", "value1");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNull(accountFormService.processFederatedIdentityUpdate());

        // Condition 3 - accountSocialAction is not null (add)
        // Add some sample values
        multivaluedMap.add("action", "add");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNull(accountFormService.processFederatedIdentityUpdate());

        // Condition 4 - model.getAlias() = providerId
        // mock
        Stream<IdentityProviderModel> stream = mock(Stream.class);
        // conditions
        when(realmModel.getIdentityProvidersStream()).thenReturn(stream);
        when(stream.anyMatch(any())).thenReturn(true);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNull(accountFormService.processFederatedIdentityUpdate());

        // Condition 5 - userModel.isEnabled = true - Throw exception
        // conditions
        when(userModel.isEnabled()).thenReturn(true);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNull(accountFormService.processFederatedIdentityUpdate());

        // Condition 6 - accountSocialAction is not null (remove) - link = null
        multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("providerId", "value1");
        multivaluedMap.add("stateChecker", "value1");
        multivaluedMap.add("action", "remove");
        // conditions
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNull(accountFormService.processFederatedIdentityUpdate());

        // Condition 7 - accountSocialAction is not null (remove) - link = not null
        // mocks
        FederatedIdentityModel federatedIdentityModel = mock(FederatedIdentityModel.class);
        // conditions
        when(keycloakSession.users().getFederatedIdentity(any(), any(), any())).thenReturn(federatedIdentityModel);
        when(userModel.credentialManager().isConfiguredFor(eq(PasswordCredentialModel.TYPE))).thenReturn(false);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNull(accountFormService.processFederatedIdentityUpdate());

        // Condition 8 - accountSocialAction is not null (remove) - link = not null
        // conditions
        when(federatedIdentityModel.getIdentityProvider()).thenReturn("anIdentityProvider");
        when(federatedIdentityModel.getUserName()).thenReturn("anUsername");
        when(userModel.getUsername()).thenReturn("username");
        when(userModel.credentialManager().isConfiguredFor(eq(PasswordCredentialModel.TYPE))).thenReturn(true);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNull(accountFormService.processFederatedIdentityUpdate());

        // Condition 9 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNotNull(accountFormService.processFederatedIdentityUpdate());

        // Condition 10 - userModel.isEnabled = true
        multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("providerId", "value1");
        multivaluedMap.add("stateChecker", "value1");
        multivaluedMap.add("action", "add");
        // mock
        mockStatic(AccountUrls.class);
        mockStatic(Urls.class);
        // condition
        when(httpRequest.getDecodedFormParameters()).thenReturn(multivaluedMap);
        when(AccountUrls.accountFederatedIdentityPage(any(URI.class), anyString())).thenReturn(uri);
        when(AccountUrls.identityProviderLinkRequest(any(URI.class), anyString(), anyString())).thenReturn(uri);
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(authResult);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processFederatedIdentityUpdate test
        assertNotNull(accountFormService.processFederatedIdentityUpdate());
    }

    @Test
    public void testResourcesPage(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // resourcesPage test
        assertNull(accountFormService.resourcesPage(resourceId));
    }

    @Test
    public void testResourceDetailPage(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // resourceDetailPage test
        assertNull(accountFormService.resourceDetailPage(resourceId));
    }

    @Test
    public void testResourceDetailPageAfterGrant(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // resourceDetailPageAfterGrant test
        assertNull(accountFormService.resourceDetailPageAfterGrant(resourceId));
    }

    @Test
    public void testResourceDetailPageAfterShare(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);

        // resourceDetailPageAfterShare test
        assertNull(accountFormService.resourceDetailPageAfterShare(resourceId));
    }

    @Test
    public void testGrantPermission(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // grantPermission test
        assertNull(accountFormService.grantPermission(resourceId, action, permissionId, requester));

        // Condition 2 - grantPermission "revoke"
        // mocks
        PermissionTicket permissionTicket1 = mock(PermissionTicket.class);
        PermissionTicket permissionTicket2 = mock(PermissionTicket.class);
        PermissionTicket permissionTicket3 = mock(PermissionTicket.class);
        PermissionTicket permissionTicket4 = mock(PermissionTicket.class);
        // Variable
        List <PermissionTicket> permissionTicketList = new ArrayList<>();
        // add values
        permissionTicketList.add(permissionTicket1);
        permissionTicketList.add(permissionTicket2);
        permissionTicketList.add(permissionTicket3);
        permissionTicketList.add(permissionTicket4);
        // conditions
        when(permissionTicket1.getId()).thenReturn("permission1");
        when(permissionTicket1.isGranted()).thenReturn(true);
        when(permissionTicket2.getId()).thenReturn("permission2");
        when(permissionTicket2.isGranted()).thenReturn(false);
        when(permissionTicket3.getId()).thenReturn("permission99");
        when(permissionTicket3.isGranted()).thenReturn(true);
        when(permissionTicket4.getId()).thenReturn("permission99");
        when(permissionTicket4.isGranted()).thenReturn(false);
        when(permissionTicketStore.find(any(), any(), any(), any(), any())).thenReturn(permissionTicketList);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // grantPermission test
        assertNull(accountFormService.grantPermission(resourceId, "revoke", null, requester));

        // Condition 3 - grantPermission "grant"
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // grantPermission test
        assertNull(accountFormService.grantPermission(resourceId, "grant", permissionId, requester));

        // Condition 4 - grantPermission "deny"
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // grantPermission test
        assertNull(accountFormService.grantPermission(resourceId, "deny", permissionId, requester));

        // Condition 5 - grantPermission "revokePolicy"
//        // constructor
//        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
//        // grantPermission test
//        assertNull(accountFormService.grantPermission(resourceId, "revokePolicy", permissionId, requester));

//        // mocks
//        Resource resource = mock(Resource.class);
//        ResourceStore resourceStore = mock(ResourceStore.class);
//        ResourceServerStore resourceServerStore = mock(ResourceServerStore.class);
//        PolicyStore policyStore = mock(PolicyStore.class);
////        ResourceServer resourceServer = mock(ResourceServer.class);
//        // mock conditions
////        when(httpRequest.getHttpMethod()).thenReturn("");
//        when(authorizationProvider.getStoreFactory().getResourceStore()).thenReturn(resourceStore);
//        when(authorizationProvider.getStoreFactory().getResourceServerStore()).thenReturn(resourceServerStore);
//        when(authorizationProvider.getStoreFactory().getResourceStore().findById(any(), any(), any())).thenReturn(resource);
//        when(authorizationProvider.getStoreFactory().getPolicyStore()).thenReturn(policyStore);
////        when(resource.getResourceServer()).thenReturn(resourceServer);
//        // constructor
//        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
////        // grantPermission "revokePolicyAll"
////        assertNull(accountFormService.grantPermission(resourceId, "revokePolicyAll", permissionId, requester));

        // Condition 7 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // grantPermission test
        assertNotNull(accountFormService.grantPermission(resourceId, action, permissionId, requester));
    }

    @Test (expected = ErrorResponseException.class)
    public void grantPermissionErrorResponseException() throws Exception {
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // grantPermission throwing error
        when(authorizationProvider.getStoreFactory().getResourceStore().findById(eq(realmModel), eq(null), eq(resourceId))).thenReturn(null);
        // grantPermission test
        accountFormService.grantPermission(resourceId, action, permissionId, requester);
    }

    @Test (expected = ErrorResponseException.class)
    public void grantPermissionErrorResponseException2() throws Exception {
        // Mocks
        Resource resource = mock(Resource.class);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // grantPermission throwing error
        when(authorizationProvider.getStoreFactory().getResourceStore().findById(eq(realmModel), eq(null), eq(resourceId))).thenReturn(resource);
        // grantPermission test
        accountFormService.grantPermission(resourceId, null, permissionId, requester);
    }

    @Test
    public void testShareResource(){
        // Condition 1
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);

        // shareResource test
        assertNull(accountFormService.shareResource(resourceId, userIds, scopes));

        // Condition 2

        // Condition 3

        // Condition 4

        // Condition 5 - Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);

        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);

        // processPasswordUpdate test
        assertNotNull(accountFormService.shareResource(resourceId, userIds, scopes));
    }

    @Test
    public void testProcessResourceActions(){
        // Condition 1
        // mocks
        Resource resource = mock(Resource.class);
        ResourceServer resourceServer = mock(ResourceServer.class);
        // mock conditions
        when(httpRequest.getHttpMethod()).thenReturn("");
        when(authorizationProvider.getStoreFactory().getResourceStore().findById(any(), any(), any())).thenReturn(resource);
        when(resource.getResourceServer()).thenReturn(resourceServer);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processResourceActions test
        assertNull(accountFormService.processResourceActions(resourceIds, action));

        // Condition 2

        // Condition 3

        // Condition 4

        // CONDITION 5 Make (auth = null)
        // AuthenticationManager
        when(AuthenticationManager.authenticateIdentityCookie(keycloakSession, realmModel, true)).thenReturn(null);
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processResourceActions test
        assertNotNull(accountFormService.processResourceActions(resourceIds, action));
    }

    @Test (expected = ErrorResponseException.class)
    public void processResourceActionsErrorResponseException1(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // processResourceActions
        assertNull(accountFormService.processResourceActions(resourceIds, action));
    }

    @Test
    public void testGetResource(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // getResource test
        assertEquals(accountFormService, accountFormService.getResource());
    }

    @Test
    public void testClose(){
        // constructor
        accountFormService = new AccountFormService(keycloakSession, clientModel, eventBuilder);
        // close
        accountFormService.close();
    }

    @Test
    public void testInit(){
        // Condition 1 - test default setup
        // constructor
        new AccountFormService(keycloakSession, clientModel, eventBuilder);

        // Condition 2 - realmModel.isIdentityFederationEnabled = false
//        AuthenticatedClientSessionModel authenticatedClientSessionModel = mock(AuthenticatedClientSessionModel.class);
//        when(keycloakSession.getProvider(eq(EventStoreProvider.class))).thenReturn(null);
//        when(realmModel.isEventsEnabled()).thenReturn(false);
//        when(realmModel.isIdentityFederationEnabled()).thenReturn(false);
//        when(clientModel.getClientId()).thenReturn("any string");
//        when(userSessionModel.getAuthenticatedClientSessionByClient(anyString())).thenReturn(authenticatedClientSessionModel);
//        // constructor
//        new AccountFormService(keycloakSession, clientModel, eventBuilder);

//        // Condition 2 - isEventsEnabled = false
//        when(realmModel.isEventsEnabled()).thenReturn(false);
//        when(realmModel.isIdentityFederationEnabled()).thenReturn(false);
//        // constructor
//        new AccountFormService(keycloakSession, clientModel, eventBuilder);

//        // Condition 4 - userSession = null
//        when(authResult.getSession()).thenReturn(null);
//        // constructor
//        new AccountFormService(keycloakSession, clientModel, eventBuilder);
    }

    @Test (expected = ForbiddenException.class)
    public void initForbiddenException1() {
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("Origin", "some value");
        // mocks conditions
        when(httpHeaders.getRequestHeaders()).thenReturn(multivaluedMap);
        when(UriUtils.getOrigin(any(URI.class))).thenReturn("value");
        // constructor
        new AccountFormService(keycloakSession, clientModel, eventBuilder);
    }

    @Test (expected = ForbiddenException.class)
    public void initForbiddenException2() {
        // variables
        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        // Add some sample values
        multivaluedMap.add("Referer", "some value");
        // mocks conditions
        when(httpRequest.getHttpMethod()).thenReturn("PUT");
        when(httpHeaders.getRequestHeaders()).thenReturn(multivaluedMap);
        when(UriUtils.getOrigin(any(URI.class))).thenReturn("value");
        // constructor
        new AccountFormService(keycloakSession, clientModel, eventBuilder);
    }
}
