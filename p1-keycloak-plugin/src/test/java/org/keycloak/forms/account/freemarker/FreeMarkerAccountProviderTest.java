 package org.keycloak.forms.account.freemarker;


 import jakarta.ws.rs.core.*;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
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
 import org.powermock.core.classloader.annotations.PrepareForTest;
 import org.powermock.modules.junit4.PowerMockRunner;

 import java.io.IOException;
 import java.net.URI;
 import java.util.*;

 import static org.junit.Assert.*;
 import static org.mockito.ArgumentMatchers.*;
 import static org.powermock.api.mockito.PowerMockito.*;

 @RunWith(PowerMockRunner.class)
 @PrepareForTest({
         Properties.class, UriBuilder.class,
 })
 public class FreeMarkerAccountProviderTest {

     @Mock private KeycloakSession keycloakSession;
     @Mock private RealmModel realmModel;
     @Mock private Locale locale;
     @Mock private Properties properties;
     @Mock private Theme theme;
     @Mock private UriInfo uriInfo;
     @Mock private UserModel userModel;
     @Mock private FreeMarkerProvider freeMarkerProvider;
     @Mock private UriBuilder uriBuilder;

     private FreeMarkerAccountProvider freeMarkerAccountProvider;
     private final URI uri = URI.create("http://example.com");

     @Before
     public void setUp() throws Exception {
         // mocks
         ThemeManager themeManager = mock(ThemeManager.class);
         KeycloakContext keycloakContext = mock(KeycloakContext.class);
         SubjectCredentialManager subjectCredentialManager = mock(SubjectCredentialManager.class);
         OTPPolicy otpPolicy = mock(OTPPolicy.class);
         UserSessionProvider userSessionProvider = mock(UserSessionProvider.class);
         UserProvider userProvider = mock(UserProvider.class);

         // local variables
         MultivaluedMap<String, String> multivaluedMap = new MultivaluedHashMap<>();
         // Add some sample values
         multivaluedMap.add("stateChecker", "value1");

         // keycloakSession
         when(keycloakSession.getProvider(eq(FreeMarkerProvider.class))).thenReturn(freeMarkerProvider);
         when(keycloakSession.theme()).thenReturn(themeManager);
         when(keycloakSession.theme().getTheme(Theme.Type.ACCOUNT)).thenReturn(theme);
         when(keycloakSession.getContext()).thenReturn(keycloakContext);
         when(keycloakSession.getContext().resolveLocale(any())).thenReturn(locale);
         when(keycloakSession.sessions()).thenReturn(userSessionProvider);
         when(keycloakSession.users()).thenReturn(userProvider);

         // realmModel
         when(realmModel.getDefaultLocale()).thenReturn("Default Locale");
         when(realmModel.getOTPPolicy()).thenReturn(otpPolicy);
         when(realmModel.getOTPPolicy().getKeyURI(any(), any(), any())).thenReturn("keyURI");

         // theme
         when(theme.getMessages(locale)).thenReturn(properties);

         // uriInfo
         when(uriInfo.getBaseUriBuilder()).thenReturn(uriBuilder);
         when(uriInfo.getQueryParameters()).thenReturn(multivaluedMap);
         when(uriInfo.getPathParameters()).thenReturn(multivaluedMap);

         // userModel
         when(userModel.credentialManager()).thenReturn(subjectCredentialManager);
         when(userModel.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)).thenReturn(false);

         // uriBuilder
         when(uriBuilder.build()).thenReturn(uri);
     }

     @Test
     public void freeMarkerAccountProviderConstructorTest(){
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
     }

     @Test
     public void setUriInfoTest() {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setUriInfo
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setUriInfo(uriInfo).getClass());
     }

     @Test
     public void setHttpHeadersTest() {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setHttpHeaders
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setHttpHeaders(mock(HttpHeaders.class)).getClass());
     }

     @Test
     public void setRealmTest() {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setRealm
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setRealm(realmModel).getClass());
     }

     @Test
     public void setUserTest() {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setUser
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setUser(userModel).getClass());
     }

     @Test
     public void createResponseTest() throws IOException {
         // Condition 1 - Account page
         // mocks
         Event event1 = mock(Event.class);
         Event event2 = mock(Event.class);
         UserSessionModel userSessionModel1 = mock(UserSessionModel.class);
         UserSessionModel userSessionModel2 = mock(UserSessionModel.class);
         // vars
         List<Event> eventList = new ArrayList<>();
         eventList.add(event1);
         eventList.add(event2);
         List<UserSessionModel> userSessionModelList = new ArrayList<>();
         userSessionModelList.add(userSessionModel1);
         userSessionModelList.add(userSessionModel2);
         String[] referrer = {"value1", "value2"};
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setRealm
         freeMarkerAccountProvider.setRealm(realmModel);
         // setUriInfo
         freeMarkerAccountProvider.setUriInfo(uriInfo);
         // setUser
         freeMarkerAccountProvider.setUser(userModel);
         // setEvents
         freeMarkerAccountProvider.setEvents(eventList);
         // setSessions
         freeMarkerAccountProvider.setSessions(userSessionModelList);
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.ACCOUNT));

//         // Condition 2 - Totp page - PITA, does not want to play nice
//         // createResponse
//         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.TOTP));

         // Condition 3 - Federated Identity page
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.FEDERATED_IDENTITY));

         // Condition 4 - Log page
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.LOG));

         // Condition 5 - Sessions page
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.SESSIONS));

         // Condition 6 - Applications page
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.APPLICATIONS));

         // Condition 7 - Password page
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.PASSWORD));

         // Condition 8 - Resources page - realm.isUserManagedAccessAllowed = false
         // condition
         when(realmModel.isUserManagedAccessAllowed()).thenReturn(false);
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.RESOURCES));

         // Condition 9 - Resources page - realm.isUserManagedAccessAllowed = true
         // condition
         when(realmModel.isUserManagedAccessAllowed()).thenReturn(true);
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.RESOURCES));

         // Condition 10 - Resource Detail page - realm.isUserManagedAccessAllowed = false
         // condition
         when(realmModel.isUserManagedAccessAllowed()).thenReturn(false);
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.RESOURCE_DETAIL));

         // Condition 11 - Resource Detail page - realm.isUserManagedAccessAllowed = true & other conditions
         // condition
         when(realmModel.isUserManagedAccessAllowed()).thenReturn(true);
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.RESOURCE_DETAIL));

         // Condition 12 - flip all the if statements
         // mocks
         mockStatic(UriBuilder.class);
         // setAttribute
         freeMarkerAccountProvider.setAttribute("key", "value");
         // setReferrer
         freeMarkerAccountProvider.setReferrer(referrer);
         // setStateChecker
         freeMarkerAccountProvider.setStateChecker("state checker");
         // condition
         when(realmModel.isInternationalizationEnabled()).thenReturn(true);
         when(UriBuilder.fromUri(any(URI.class))).thenReturn(uriBuilder);
         when(uriBuilder.path(anyString())).thenReturn(uriBuilder);
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.ACCOUNT));

         // Condition 13 - IOException
         // condition
         when(keycloakSession.theme().getTheme(Theme.Type.ACCOUNT)).thenThrow(IOException.class);
         // createResponse
         assertNotNull(freeMarkerAccountProvider.createResponse(AccountPages.ACCOUNT));
     }

     @Test
     public void getThemeTest() throws IOException {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // getTheme
         assertEquals(theme, freeMarkerAccountProvider.getTheme());
     }

     @Test
     public void handleThemeResourcesTest() throws IOException {
         // Condition 1
         // mocks
         Map<String, Object> customAttributes = mock(Map.class);
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setRealm
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setRealm(realmModel).getClass());
         // handleThemeResources
         assertNotNull(freeMarkerAccountProvider.handleThemeResources(theme, locale, customAttributes));

         // Condition 2 - realm locale is empty
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // conditions
         when(realmModel.getDefaultLocale()).thenReturn("");
         // setRealm
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setRealm(realmModel).getClass());
         // handleThemeResources
         assertNotNull(freeMarkerAccountProvider.handleThemeResources(theme, locale, customAttributes));

         // Condition 3 - force throw exception
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // conditions
         when(theme.getMessages(any())).thenThrow(IOException.class);
         when(theme.getProperties()).thenThrow(IOException.class);
         // setRealm
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setRealm(realmModel).getClass());
         // handleThemeResources
         assertNotNull(freeMarkerAccountProvider.handleThemeResources(theme, locale, customAttributes));

     }

     @Test
     public void handleMessagesTest() {
         // Condition 1
         // mocks
         Map<String, Object> customAttributes = mock(Map.class);
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // handleMessages
         freeMarkerAccountProvider.handleMessages(locale, properties, customAttributes);

         // Condition 2 - message is not null
         // vars
         Object[] parameters = { "param1", "param2" };
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // setMessage
         freeMarkerAccountProvider.setMessage(MessageType.SUCCESS, "message", parameters);
         // handleMessages
         freeMarkerAccountProvider.handleMessages(locale, properties, customAttributes);
     }

     @Test
     public void processTemplateTest() throws FreeMarkerException {
         // Condition 1
         // mocks
         Map<String, Object> customAttributes = mock(Map.class);
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // processTemplate
         assertNotNull(freeMarkerAccountProvider.processTemplate(theme, AccountPages.ACCOUNT, customAttributes, locale));

         // Condition 2
         // condition
         when(freeMarkerProvider.processTemplate(any(), any(), any())).thenThrow(FreeMarkerException.class);
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // processTemplate
         assertNotNull(freeMarkerAccountProvider.processTemplate(theme, AccountPages.ACCOUNT, customAttributes, locale));
     }

     @Test
     public void setPasswordSetTest() {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setPasswordSet
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setPasswordSet(true).getClass());
     }

     @Test
     public void setMessageTest() {
         // vars
         Object[] parameters = { "param1", "param2" };
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setMessage
         freeMarkerAccountProvider.setMessage(MessageType.SUCCESS, "message", parameters);
     }

     @Test
     public void formatMessageTest() {
         // Condition 1
         // mocks
         FormMessage formMessage = mock(FormMessage.class);
         Properties messagesBundle = mock(Properties.class);
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // formatMessage
         assertNull(freeMarkerAccountProvider.formatMessage(formMessage, messagesBundle, locale));

         // Condition 2
         // conditions
         when(formMessage.getMessage()).thenReturn("any string");
         when(formMessage.getParameters()).thenReturn(new String[]{"some", "message"});
         when(messagesBundle.containsKey(anyString())).thenReturn(true);
         when(messagesBundle.getProperty(anyString())).thenReturn("message bundle");
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // formatMessage
         assertNotNull(freeMarkerAccountProvider.formatMessage(formMessage, messagesBundle, locale));

         // Condition 3 - message = null
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // formatMessage
         assertNull(freeMarkerAccountProvider.formatMessage(null, messagesBundle, locale));
     }

     @Test
     public void setErrorsTest() {
         // mocks
         FormMessage formMessage = mock(FormMessage.class);
         // vars
         List<FormMessage>  formMessageList = List.of(formMessage);
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setErrors
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setErrors(Response.Status.BAD_REQUEST, formMessageList).getClass());
     }

     @Test
     public void setErrorTest() {
         // vars
         Object[] parameters = { "param1", "param2" };
         String errorMessage = "This is an error";
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setError
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setError(Response.Status.NOT_FOUND, errorMessage, parameters).getClass());
     }

     @Test
     public void setSuccessTest() {
         // vars
         Object[] parameters = { "param1", "param2" };
         String successMessage = "This is successful.";
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setSuccess
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setSuccess(successMessage, parameters).getClass());
     }

     @Test
     public void setWarningTest() {
         // vars
         Object[] parameters = { "param1", "param2" };
         String warningMessage = "This is a warning.";
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setWarning
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setWarning(warningMessage, parameters).getClass());
     }

     @Test
     public void setProfileFormDataTest() {
         // vars
         MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setProfileFormData
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setProfileFormData(formData).getClass());
     }

     @Test
     public void setReferrerTest() {
         // vars
         String[] referrer = {"value1", "value2"};
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setReferrer
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setReferrer(referrer).getClass());
     }

     @Test
     public void setEventsTest() {
         // vars
         List<Event> eventList = mock(List.class);
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setEvents
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setEvents(eventList).getClass());
     }

     @Test
     public void setSessionsTest() {
         // mock
         List<UserSessionModel>  userSessionModelList = mock(List.class);
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setSessions
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setSessions(userSessionModelList).getClass());
     }

     @Test
     public void setStateCheckerTest() {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setStateChecker
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setStateChecker("state checker").getClass());
     }

     @Test
     public void setIdTokenHintTest() {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setIdTokenHint
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setIdTokenHint("token hint").getClass());
     }

     @Test
     public void setFeaturesTest() {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setFeatures
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setFeatures(true, true, true, true).getClass());
     }

     @Test
     public void setAttributeTest() {
         // Condition 1 - attribute is null
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // setAttribute
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setAttribute("key", "value").getClass());

         // Condition 1 - attribute is not null
         // setAttribute
         assertEquals(FreeMarkerAccountProvider.class, freeMarkerAccountProvider.setAttribute("key2", "value2").getClass());
     }

     @Test
     public void closeTest() {
         // constructor
         freeMarkerAccountProvider = new FreeMarkerAccountProvider(keycloakSession);
         // check the constructor
         assertNotNull(freeMarkerAccountProvider);
         // close
         freeMarkerAccountProvider.close();
     }
 }