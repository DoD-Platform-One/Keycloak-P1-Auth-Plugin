package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.NewObjectProvider;
import org.apache.commons.io.FilenameUtils;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.keycloak.http.FormPartValue;
import org.keycloak.http.HttpRequest;
import org.jboss.resteasy.spi.ResteasyAsynchronousContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.common.ClientConnection;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.InvalidationHandler;
import org.keycloak.provider.Provider;
import org.keycloak.services.clientpolicy.ClientPolicyManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;

import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.vault.VaultTranscriber;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.yaml.snakeyaml.Yaml;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static dod.p1.keycloak.utils.Utils.setupX509Mocks;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import javax.security.auth.x500.X500Principal;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ Yaml.class, FileInputStream.class, File.class, CommonConfig.class, X509Tools.class, FilenameUtils.class, NewObjectProvider.class })
@PowerMockIgnore("javax.management.*")
public class RegistrationValidationTest {

    @Before
    public void setup() throws Exception {
        setupX509Mocks();
        setupFileMocks();
    }

    public ValidationContext setupVariables(String[] errorEvent, List<FormMessage> errors,
            MultivaluedMap<String, String> multivaluedMap) {
        return new ValidationContext() {
            final RealmModel realmModel = mock(RealmModel.class);

            @Override
            public void validationError(MultivaluedMap<String, String> multivaluedMap, List<FormMessage> list) {
                errors.addAll(list);
            }

            @Override
            public void error(String s) {
                errorEvent[0] = s;
            }

            @Override
            public void success() {

            }

            @Override
            public void excludeOtherErrors() {

            }

            @Override
            public EventBuilder getEvent() {
                return mock(EventBuilder.class);
            }

            @Override
            public EventBuilder newEvent() {
                return null;
            }

            @Override
            public AuthenticationExecutionModel getExecution() {
                return null;
            }

            @Override
            public UserModel getUser() {
                return null;
            }

            @Override
            public void setUser(UserModel userModel) {

            }

            @Override
            public RealmModel getRealm() {
                return realmModel;
            }

            @Override
            public AuthenticationSessionModel getAuthenticationSession() {
                return mock(AuthenticationSessionModel.class);
            }

            @Override
            public ClientConnection getConnection() {
                return mock(ClientConnection.class);
            }

            @Override
            public UriInfo getUriInfo() {
                return mock(UriInfo.class);
            }

            @Override
            public KeycloakSession getSession() {
                return new KeycloakSession() {
                    @Override
                    public KeycloakContext getContext() {
                        return null;
                    }
                    @Override
                    public SingleUseObjectProvider singleUseObjects() {
                        return null;
                    }

                    @Override
                    public GroupProvider groups() {
                        return null;
                    }

                    @Override
                    public RoleProvider roles() {
                        return null;
                    }

                    @Override
                    public KeycloakTransactionManager getTransactionManager() {
                        return null;
                    }

                    @Override
                    public <T extends Provider> T getProvider(Class<T> aClass) {
                        return null;
                    }

                    @Override
                    public <T extends Provider> T getProvider(Class<T> aClass, String s) {
                        return null;
                    }

                    @Override
                    public <T extends Provider> T getComponentProvider(Class<T> aClass, String componentId) {
                        return null;
                    }

                    @Override
                    public <T extends Provider> T getComponentProvider(Class<T> aClass, String componentId, Function<KeycloakSessionFactory,ComponentModel> aFunction) {
                        return null;
                    }

                    @Override
                    public <T extends Provider> T getProvider(Class<T> aClass, ComponentModel componentModel) {
                        return null;
                    }

                    @Override
                    public <T extends Provider> Set<String> listProviderIds(Class<T> aClass) {
                        return null;
                    }

                    @Override
                    public <T extends Provider> Set<T> getAllProviders(Class<T> aClass) {
                        return null;
                    }

                    @Override
                    public Class<? extends Provider> getProviderClass(String s) {
                        return null;
                    }

                    @Override
                    public Object getAttribute(String s) {
                        return null;
                    }

                    @Override
                    public <T> T getAttribute(String s, Class<T> aClass) {
                        return null;
                    }

                    @Override
                    public Object removeAttribute(String s) {
                        return null;
                    }

                    @Override
                    public void setAttribute(String s, Object o) {

                    }

                    @Override
                    public Map<String, Object> getAttributes() {
                        return null;
                    }

                    @Override
                    public void invalidate(InvalidationHandler.InvalidableObjectType type, Object... params) {

                    }

                    @Override
                    public void enlistForClose(Provider provider) {

                    }

                    @Override
                    public KeycloakSessionFactory getKeycloakSessionFactory() {
                        return null;
                    }

                    @Override
                    public RealmProvider realms() {
                        return null;
                    }

                    @Override
                    public ClientProvider clients() {
                        return null;
                    }

                    @Override
                    public UserSessionProvider sessions() {
                        return null;
                    }

                    @Override
                    public AuthenticationSessionProvider authenticationSessions() {
                        return null;
                    }

                    @Override
                    public void close() {

                    }

                    @Override
                    public UserProvider users() {
                        UserProvider userProvider = mock(UserProvider.class);
                        when(userProvider.getUserByEmail(realmModel, "test@ss.usafa.edu"))
                                .thenReturn(mock(UserModel.class));
                        return userProvider;
                    }

                    @Override
                    public ClientScopeProvider clientScopes() {
                        return null;
                    }

                    //@Override
                    public UserFederatedStorageProvider userFederatedStorage() {
                        return null;
                    }

                    @Override
                    public KeyManager keys() {
                        return null;
                    }

                    @Override
                    public ThemeManager theme() {
                        return null;
                    }

                    @Override
                    public TokenManager tokens() {
                        return null;
                    }

                    @Override
                    public VaultTranscriber vault() {
                        return null;
                    }

                    @Override
                    public ClientPolicyManager clientPolicy() {
                        return null;
                    }

                    @Override
                    public boolean isClosed() { return false; }

                    @Override
                    public UserLoginFailureProvider loginFailures() {
                        return null;
                    }

                };
            }

            @Override
            public HttpRequest getHttpRequest() {
                return new HttpRequest() {
                    @Override
                    public HttpHeaders getHttpHeaders() {
                        return null;
                    }

                    @Override
                    public X509Certificate[] getClientCertificateChain() {
                        return new X509Certificate[0];
                    }

                    public MultivaluedMap<String, String> getMutableHeaders() {
                        return null;
                    }

                    public InputStream getInputStream() {
                        return null;
                    }
                    public void setInputStream(InputStream inputStream) {

                    }

                    @Override
                    public ResteasyUriInfo getUri() {
                        return null;
                    }

                    @Override
                    public String getHttpMethod() {
                        return null;
                    }

                    public void setHttpMethod(String s) {

                    }

                    public void setRequestUri(URI uri) throws IllegalStateException {

                    }

                    public void setRequestUri(URI uri, URI uri1) throws IllegalStateException {

                    }

                    public MultivaluedMap<String, String> getFormParameters() {
                        return null;
                    }

                    @Override
                    public MultivaluedMap<String, String> getDecodedFormParameters() {
                        return multivaluedMap;
                    }

                    @Override
                    public MultivaluedMap<String, FormPartValue> getMultiPartFormParameters() {
                        return null;
                    }

                    public boolean formParametersRead() {
                        return false;
                    }

                    public Object getAttribute(String s) {
                        return null;
                    }

                    public void setAttribute(String s, Object o) {

                    }

                    public void removeAttribute(String s) {

                    }

                    public Enumeration<String> getAttributeNames() {
                        return null;
                    }

                    public ResteasyAsynchronousContext getAsyncContext() {
                        return null;
                    }

                    public boolean isInitial() {
                        return false;
                    }

                    public void forward(String s) {

                    }

                    public boolean wasForwarded() {
                        return false;
                    }

                    public String getRemoteAddress() {
                        return null;
                    }

                    public String getRemoteHost() {
                        return null;
                    }
                };
            }

            @Override
            public AuthenticatorConfigModel getAuthenticatorConfig() {
                return null;
            }

        };
    }


    @Test
    public void testInvalidFields() {
        String[] errorEvent = new String[1];
        List<FormMessage> errors = new ArrayList<>();
        MultivaluedMapImpl<String, String> valueMap = new MultivaluedMapImpl<>();
        ValidationContext context = setupVariables(errorEvent, errors, valueMap);
        RegistrationValidation validation = new RegistrationValidation();
        validation.validate(context);
        Assert.assertEquals(errorEvent[0], Errors.INVALID_REGISTRATION);
        Set<String> errorFields = errors.stream().map(FormMessage::getField).collect(Collectors.toSet());
        Assert.assertTrue(errorFields.contains("firstName"));
        Assert.assertTrue(errorFields.contains("lastName"));
        Assert.assertTrue(errorFields.contains("username"));
        Assert.assertTrue(errorFields.contains("user.attributes.affiliation"));
        Assert.assertTrue(errorFields.contains("user.attributes.rank"));
        Assert.assertTrue(errorFields.contains("user.attributes.organization"));
        Assert.assertTrue(errorFields.contains("email"));
        Assert.assertTrue(errorFields.contains("confirmEmail"));
        Assert.assertEquals(9, errors.size());
    }

    @Test
    public void testEmailValidation() {
        String[] errorEvent = new String[1];
        List<FormMessage> errors = new ArrayList<>();
        MultivaluedMapImpl<String, String> valueMap = new MultivaluedMapImpl<>();
        valueMap.putSingle("firstName", "Jone");
        valueMap.putSingle("lastName", "Doe");
        valueMap.putSingle("username", "tester");
        valueMap.putSingle("user.attributes.affiliation", "AF");
        valueMap.putSingle("user.attributes.rank", "E2");
        valueMap.putSingle("user.attributes.organization", "Com");
        valueMap.putSingle("user.attributes.location", "42");
        valueMap.putSingle("email", "test@gmail.com");
        valueMap.putSingle("confirmEmail", "test@gmail.com");

        ValidationContext context = setupVariables(errorEvent, errors, valueMap);

        RegistrationValidation validation = new RegistrationValidation();
        validation.validate(context);
        Assert.assertEquals(0, errors.size());

        // test an email address already in use
        valueMap.putSingle("email", "test@ss.usafa.edu");
        valueMap.putSingle("confirmEmail", "test@ss.usafa.edu");
        errorEvent = new String[1];
        errors = new ArrayList<>();
        context = setupVariables(errorEvent, errors, valueMap);

        validation = new RegistrationValidation();
        validation.validate(context);
        Assert.assertEquals(Errors.EMAIL_IN_USE, errorEvent[0]);
        Assert.assertEquals(1, errors.size());
        Assert.assertEquals(RegistrationPage.FIELD_EMAIL, errors.get(0).getField());

    }

    @Test
    public void testGroupAutoJoinByEmail() {
        String[] errorEvent = new String[1];
        List<FormMessage> errors = new ArrayList<>();
        MultivaluedMapImpl<String, String> valueMap = new MultivaluedMapImpl<>();
        valueMap.putSingle("firstName", "Jone");
        valueMap.putSingle("lastName", "Doe");
        valueMap.putSingle("username", "tester");
        valueMap.putSingle("user.attributes.affiliation", "AF");
        valueMap.putSingle("user.attributes.rank", "E2");
        valueMap.putSingle("user.attributes.organization", "Com");
        valueMap.putSingle("user.attributes.location", "42");
        valueMap.putSingle("email", "test@gmail.com");
        valueMap.putSingle("confirmEmail", "test@gmail.com");

        ValidationContext context = setupVariables(errorEvent, errors, valueMap);

        RegistrationValidation validation = new RegistrationValidation();
        validation.validate(context);
        Assert.assertEquals(0, errors.size());

        // test valid IL2 email with custom domains
        valueMap.putSingle("email", "rando@supercool.unicorns.com");
        valueMap.putSingle("confirmEmail", "rando@supercool.unicorns.com");
        errorEvent = new String[1];
        errors = new ArrayList<>();
        context = setupVariables(errorEvent, errors, valueMap);

        validation = new RegistrationValidation();
        validation.validate(context);
        Assert.assertNull(errorEvent[0]);
        Assert.assertEquals(0, errors.size());

        // test valid IL4 email with custom domains
        valueMap.putSingle("email", "test22@ss.usafa.edu");
        valueMap.putSingle("confirmEmail", "test22@ss.usafa.edu");
        errorEvent = new String[1];
        errors = new ArrayList<>();
        context = setupVariables(errorEvent, errors, valueMap);

        validation = new RegistrationValidation();
        validation.validate(context);
        Assert.assertNull(errorEvent[0]);
        Assert.assertEquals(0, errors.size());

        // Test existing x509 registration
        errorEvent = new String[1];
        errors = new ArrayList<>();
        context = setupVariables(errorEvent, errors, valueMap);

        PowerMockito.when(X509Tools.isX509Registered(any(FormContext.class))).thenReturn(true);

        validation = new RegistrationValidation();
        validation.validate(context);
        Assert.assertEquals(Errors.INVALID_REGISTRATION, errorEvent[0]);
    }

    @Test
    public void testSuccess() {
    }

    @Test
    public void testBuildPage() throws GeneralSecurityException{
        RegistrationValidation subject = new RegistrationValidation();
        FormContext context = mock(FormContext.class);
        KeycloakSession kcSession = mock(KeycloakSession.class);
        HttpRequest httpRequest = mock(HttpRequest.class);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(context.getHttpRequest().getClientCertificateChain()).thenReturn(new X509Certificate[]{});
        when(context.getSession()).thenReturn(kcSession);
        X509ClientCertificateLookup provider = mock(X509ClientCertificateLookup.class);
        when(kcSession.getProvider(X509ClientCertificateLookup.class)).thenReturn(provider);
        when(provider.getCertificateChain(context.getHttpRequest())).thenReturn(new X509Certificate[]{});
        X509Tools tools = mock(X509Tools.class);
        when(tools.getX509Username(context)).thenReturn("X509Username");
        LoginFormsProvider form = mock(LoginFormsProvider.class);
        subject.buildPage(context, form);


        Assert.assertTrue(provider.getCertificateChain(context.getHttpRequest()).length == 0);
//        verify(tools,times(1)).getX509Username(context);
//        verify(form, times(1)).setAttribute("cacIdentity", "X509Username");
    }


//    @Test
//    public void testBuildFormFromX509() {
//        FormContext context = mock(FormContext.class);
//        X509Certificate[] certs = new X509Certificate[]{mock(X509Certificate.class)};
//        when(X509Tools.getX509Username(any(FormContext.class))).thenReturn("X509Username");
//        when(context.getHttpRequest().getDecodedFormParameters()).thenReturn(mock(MultivaluedMap.class));
//        when(certs[0].getSubjectX500Principal()).thenReturn(mock(X500Principal.class));
//        when(certs[0].getSubjectX500Principal().getName()).thenReturn("Name.Principal,OU=USAF");
//        when(certs[0].getIssuerX500Principal()).thenReturn(mock(X500Principal.class));
//
//        RegistrationValidation subject = new RegistrationValidation();
//        MultivaluedMap actual = subject.buildFormFromX509(context, certs);
//
//        Assert.assertTrue("X509Username".equals(actual.getFirst("cacIdentity")));
//        Assert.assertTrue("Name".equals(actual.getFirst(RegistrationPage.FIELD_LAST_NAME)));
//        Assert.assertTrue("Principal".equals(actual.getFirst(RegistrationPage.FIELD_FIRST_NAME)));
//        Assert.assertTrue("US Air Force".equals(actual.getFirst(RegistrationValidation.USER_ATTRIBUTES_AFFILIATION)));
//    }

    @Test
    public void testGetDisplayType() {
        RegistrationValidation subject = new RegistrationValidation();
        Assert.assertEquals(subject.getDisplayType(), "Platform One Registration Validation");
    }

    @Test
    public void testGetId() {
        RegistrationValidation subject = new RegistrationValidation();
        Assert.assertEquals(subject.getId(), "registration-validation-action");
    }

    @Test
    public void testIsConfigurable() {
        RegistrationValidation subject = new RegistrationValidation();
        Assert.assertFalse(subject.isConfigurable());
    }

    @Test
    public void testGetRequirementChoices() {
        RegistrationValidation subject = new RegistrationValidation();
        AuthenticationExecutionModel.Requirement[] expected = { AuthenticationExecutionModel.Requirement.REQUIRED };
        Assert.assertEquals(subject.getRequirementChoices(), expected);
    }

    @Test
    public void testMattermostUsernameValidation() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        List<FormMessage> messageList = new ArrayList<FormMessage>();
        RegistrationValidation subject = new RegistrationValidation();
        subject.mattermostUsernameValidation(messageList, "TestUser1");
        Method method = RegistrationValidation.class.getDeclaredMethod("mattermostUsernameValidation", List.class, String.class);

        Assert.assertTrue(messageList.size() == 0);
    }


    @Test
    public void testNegativeMattermostUsernameValidation() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        List<FormMessage> messageList = new ArrayList<FormMessage>();
        RegistrationValidation subject = new RegistrationValidation();
        subject.mattermostUsernameValidation(messageList, "#a");

        Assert.assertTrue(messageList.size() == 3);
    }
}
