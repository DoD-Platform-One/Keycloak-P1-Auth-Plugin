package org.keycloak.forms.account.freemarker;

import jakarta.ws.rs.core.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.events.Event;
import org.keycloak.forms.account.AccountPages;
import org.keycloak.forms.login.MessageType;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.theme.FreeMarkerException;
import org.keycloak.theme.Theme;
import org.keycloak.theme.freemarker.FreeMarkerProvider;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the FreeMarkerAccountProvider class.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class FreeMarkerAccountProviderTest {

    @Mock
    private KeycloakSession keycloakSession;

    @Mock
    private RealmModel realmModel;

    @Mock
    private Locale locale;

    @Mock
    private Properties properties;

    @Mock
    private Theme theme;

    @Mock
    private UriInfo uriInfo;

    @Mock
    private UserModel userModel;

    @Mock
    private FreeMarkerProvider freeMarkerProvider;

    @Mock
    private UriBuilder uriBuilder;

    private FreeMarkerAccountProvider freeMarkerAccountProvider;
    private final URI uri = URI.create("http://example.com");

    @BeforeEach
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        // Create a fake ThemeManager to be returned from keycloakSession.theme()
        ThemeManager themeManager = mock(ThemeManager.class);
        KeycloakContext keycloakContext = mock(KeycloakContext.class);
        SubjectCredentialManager subjectCredentialManager = mock(SubjectCredentialManager.class);
        OTPPolicy otpPolicy = mock(OTPPolicy.class);
        UserSessionProvider userSessionProvider = mock(UserSessionProvider.class);
        UserProvider userProvider = mock(UserProvider.class);

        MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
        multivaluedMap.add("stateChecker", "value1");

        when(keycloakSession.getProvider(eq(FreeMarkerProvider.class))).thenReturn(freeMarkerProvider);
        when(keycloakSession.theme()).thenReturn(themeManager);
        when(themeManager.getTheme(Theme.Type.ACCOUNT)).thenReturn(theme);

        when(keycloakSession.getContext()).thenReturn(keycloakContext);
        when(keycloakContext.resolveLocale(any())).thenReturn(locale);
        when(keycloakSession.sessions()).thenReturn(userSessionProvider);
        when(keycloakSession.users()).thenReturn(userProvider);

        when(realmModel.getDefaultLocale()).thenReturn("Default Locale");
        when(realmModel.getOTPPolicy()).thenReturn(otpPolicy);

        // By default, let's have theme.getMessages(locale) return 'properties'
        when(theme.getMessages(locale)).thenReturn(properties);

        when(uriInfo.getBaseUriBuilder()).thenReturn(uriBuilder);
        when(uriInfo.getBaseUri()).thenReturn(uri);
        when(uriInfo.getQueryParameters()).thenReturn(multivaluedMap);
        when(uriInfo.getPathParameters()).thenReturn(multivaluedMap);

        when(userModel.credentialManager()).thenReturn(subjectCredentialManager);
        when(subjectCredentialManager.isConfiguredFor(OTPCredentialModel.TYPE)).thenReturn(false);

        when(uriBuilder.build()).thenReturn(uri);
    }

    @Test
    public void freeMarkerAccountProviderConstructorTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider,
            "FreeMarkerAccountProvider constructor should not return null");
    }

    @Test
    public void setUriInfoTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider, "Provider should be instantiated");
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setUriInfo(uriInfo).getClass(),
            "setUriInfo should return an instance of FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setHttpHeadersTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setHttpHeaders(mock(HttpHeaders.class)).getClass(),
            "setHttpHeaders should return an instance of FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setRealmTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setRealm(realmModel).getClass(),
            "setRealm should return an instance of FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setUserTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setUser(userModel).getClass(),
            "setUser should return an instance of FreeMarkerAccountProvider"
        );
    }

    @Test
    public void createResponseTest() throws IOException {
        Event event1 = mock(Event.class);
        Event event2 = mock(Event.class);
        UserSessionModel userSessionModel1 = mock(UserSessionModel.class);
        UserSessionModel userSessionModel2 = mock(UserSessionModel.class);

        List<Event> eventList = new ArrayList<>();
        eventList.add(event1);
        eventList.add(event2);

        List<UserSessionModel> userSessionModelList = new ArrayList<>();
        userSessionModelList.add(userSessionModel1);
        userSessionModelList.add(userSessionModel2);

        String[] referrer = {"value1", "value2"};

        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);

        freeMarkerAccountProvider.setRealm(realmModel);
        freeMarkerAccountProvider.setUriInfo(uriInfo);
        freeMarkerAccountProvider.setUser(userModel);
        freeMarkerAccountProvider.setEvents(eventList);
        freeMarkerAccountProvider.setSessions(userSessionModelList);

        // Simulate normal creation
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.ACCOUNT),
            "createResponse for ACCOUNT should not return null"
        );
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.FEDERATED_IDENTITY),
            "createResponse for FEDERATED_IDENTITY should not return null"
        );
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.LOG),
            "createResponse for LOG should not return null"
        );
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.SESSIONS),
            "createResponse for SESSIONS should not return null"
        );
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.APPLICATIONS),
            "createResponse for APPLICATIONS should not return null"
        );
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.PASSWORD),
            "createResponse for PASSWORD should not return null"
        );

        // RE: resources
        when(realmModel.isUserManagedAccessAllowed()).thenReturn(false);
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.RESOURCES),
            "Should not return null even if user-managed access disallowed"
        );

        when(realmModel.isUserManagedAccessAllowed()).thenReturn(true);
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.RESOURCES),
            "Should not return null if user-managed access allowed"
        );

        when(realmModel.isUserManagedAccessAllowed()).thenReturn(false);
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.RESOURCE_DETAIL),
            "Should not return null if user-managed access disallowed for RESOURCE_DETAIL"
        );

        when(realmModel.isUserManagedAccessAllowed()).thenReturn(true);
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.RESOURCE_DETAIL),
            "Should not return null if user-managed access allowed for RESOURCE_DETAIL"
        );

        freeMarkerAccountProvider.setAttribute("key", "value");
        freeMarkerAccountProvider.setReferrer(referrer);
        freeMarkerAccountProvider.setStateChecker("state checker");
        when(realmModel.isInternationalizationEnabled()).thenReturn(true);

        // Let uriBuilder.path(...) just return itself for simplicity
        when(uriBuilder.path(anyString())).thenReturn(uriBuilder);

        // *** Test the IOException path for getTheme(). We expect a server-error response but not a crash.
        when(keycloakSession.theme().getTheme(Theme.Type.ACCOUNT)).thenThrow(IOException.class);
        assertNotNull(
            freeMarkerAccountProvider.createResponse(AccountPages.ACCOUNT),
            "createResponse should return a non-null response even if IOException occurs"
        );
    }

    @Test
    public void getThemeTest() throws IOException {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            theme,
            freeMarkerAccountProvider.getTheme(),
            "getTheme should return the mocked theme"
        );
    }

    @Test
    public void handleThemeResourcesTest() throws IOException {
        Map<String, Object> customAttributes = new HashMap<>();
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);

        freeMarkerAccountProvider.setRealm(realmModel);
        assertNotNull(
            freeMarkerAccountProvider.handleThemeResources(theme, locale, customAttributes),
            "handleThemeResources should not return null under normal conditions"
        );

        // Realm default locale is empty
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        when(realmModel.getDefaultLocale()).thenReturn("");
        freeMarkerAccountProvider.setRealm(realmModel);
        assertNotNull(
            freeMarkerAccountProvider.handleThemeResources(theme, locale, customAttributes),
            "handleThemeResources should not return null if realm's default locale is empty"
        );

        // Force exception for messages and properties loading
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        freeMarkerAccountProvider.setRealm(realmModel);
        when(theme.getMessages(any())).thenThrow(IOException.class);
        when(theme.getProperties()).thenThrow(IOException.class);
        assertNotNull(
            freeMarkerAccountProvider.handleThemeResources(theme, locale, customAttributes),
            "handleThemeResources should not return null even if an IOException occurs"
        );
    }

    @Test
    public void handleMessagesTest() {
        Map<String, Object> customAttributes = new HashMap<>();
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);

        // no messages set => nothing special
        freeMarkerAccountProvider.handleMessages(locale, properties, customAttributes);

        // Now add a message
        Object[] parameters = { "param1", "param2" };
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        freeMarkerAccountProvider.setMessage(MessageType.SUCCESS, "message", parameters);
        freeMarkerAccountProvider.handleMessages(locale, properties, customAttributes);
    }

    @Test
    public void processTemplateTest() throws FreeMarkerException {
        Map<String, Object> customAttributes = new HashMap<>();
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);

        // Normal template rendering
        when(freeMarkerProvider.processTemplate(any(), any(), any())).thenReturn("template content");
        Response response = freeMarkerAccountProvider.processTemplate(theme, AccountPages.ACCOUNT, customAttributes, locale);
        assertNotNull(response, "processTemplate(ACCOUNT) should not return null");

        // If processing throws FreeMarkerException, we expect a server error
        when(freeMarkerProvider.processTemplate(any(), any(), any())).thenThrow(FreeMarkerException.class);
        response = freeMarkerAccountProvider.processTemplate(theme, AccountPages.ACCOUNT, customAttributes, locale);
        assertEquals(
            Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
            response.getStatus(),
            "Should return server error when FreeMarkerException occurs"
        );
    }

    @Test
    public void setPasswordSetTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setPasswordSet(true).getClass(),
            "setPasswordSet should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setMessageTest() {
        Object[] parameters = { "param1", "param2" };
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        freeMarkerAccountProvider.setMessage(MessageType.SUCCESS, "message", parameters);
        // no assertion needed beyond no crash
    }

    @Test
    public void formatMessageTest() {
        FormMessage formMessage = mock(FormMessage.class);
        Properties messagesBundle = mock(Properties.class);
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);

        // if message is null => returns null
        assertNull(
            freeMarkerAccountProvider.formatMessage(null, messagesBundle, locale),
            "formatMessage should return null when FormMessage is null"
        );

        // if message is empty => returns the raw message
        assertNull(
            freeMarkerAccountProvider.formatMessage(formMessage, messagesBundle, locale),
            "formatMessage should return null if formMessage.getMessage() is empty"
        );

        // Now give the message a key and parameters
        when(formMessage.getMessage()).thenReturn("some.key");
        when(formMessage.getParameters()).thenReturn(new String[]{"some", "message"});
        when(messagesBundle.containsKey(anyString())).thenReturn(true);
        when(messagesBundle.getProperty(anyString())).thenReturn("message bundle");

        assertNotNull(
            freeMarkerAccountProvider.formatMessage(formMessage, messagesBundle, locale),
            "formatMessage should not return null when message key is in bundle"
        );
    }

    @Test
    public void setErrorsTest() {
        FormMessage formMessage = mock(FormMessage.class);
        List<FormMessage> formMessageList = List.of(formMessage);

        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setErrors(Response.Status.BAD_REQUEST, formMessageList).getClass(),
            "setErrors should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setErrorTest() {
        Object[] parameters = { "param1", "param2" };
        String errorMessage = "This is an error";

        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setError(Response.Status.NOT_FOUND, errorMessage, parameters).getClass(),
            "setError should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setSuccessTest() {
        Object[] parameters = { "param1", "param2" };
        String successMessage = "This is successful.";

        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setSuccess(successMessage, parameters).getClass(),
            "setSuccess should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setWarningTest() {
        Object[] parameters = { "param1", "param2" };
        String warningMessage = "This is a warning.";

        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setWarning(warningMessage, parameters).getClass(),
            "setWarning should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setProfileFormDataTest() {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();

        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setProfileFormData(formData).getClass(),
            "setProfileFormData should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setReferrerTest() {
        String[] referrer = {"value1", "value2"};

        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setReferrer(referrer).getClass(),
            "setReferrer should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setEventsTest() {
        List<Event> eventList = mock(List.class);

        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setEvents(eventList).getClass(),
            "setEvents should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setSessionsTest() {
        List<UserSessionModel> userSessionModelList = mock(List.class);

        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setSessions(userSessionModelList).getClass(),
            "setSessions should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setStateCheckerTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setStateChecker("state checker").getClass(),
            "setStateChecker should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setIdTokenHintTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setIdTokenHint("token hint").getClass(),
            "setIdTokenHint should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setFeaturesTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setFeatures(true, true, true, true).getClass(),
            "setFeatures should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void setAttributeTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);

        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setAttribute("key", "value").getClass(),
            "setAttribute should return FreeMarkerAccountProvider"
        );
        // Another attribute
        assertEquals(
            FreeMarkerAccountProvider.class,
            freeMarkerAccountProvider.setAttribute("key2", "value2").getClass(),
            "setAttribute should return FreeMarkerAccountProvider"
        );
    }

    @Test
    public void closeTest() {
        freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
        assertNotNull(freeMarkerAccountProvider);
        freeMarkerAccountProvider.close();
        // No specific assertions; just ensure no exceptions
    }
}
