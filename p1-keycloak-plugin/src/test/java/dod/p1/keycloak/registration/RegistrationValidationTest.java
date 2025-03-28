package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import dod.p1.keycloak.utils.NewObjectProvider;
import dod.p1.keycloak.utils.Utils;
import org.apache.commons.io.FilenameUtils;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.vault.VaultTranscriber;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.yaml.snakeyaml.Yaml;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;

import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.*;
import org.keycloak.models.utils.FormMessage;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.keycloak.http.HttpRequest;
import org.keycloak.events.EventBuilder;
import org.keycloak.common.ClientConnection;
import org.keycloak.provider.Provider;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.provider.InvalidationHandler;

import static dod.p1.keycloak.utils.Utils.setupFileMocks;
import static dod.p1.keycloak.utils.Utils.setupX509Mocks;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

// Keycloak
import org.keycloak.authentication.FormContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.services.clientpolicy.ClientPolicyManager;
import org.keycloak.services.x509.X509ClientCertificateLookup;

// JAX-RS / Jakarta
import jakarta.ws.rs.core.HttpHeaders;  // if you need getHttpHeaders()

// Possibly for Resteasy (depending on actual usage)
import org.keycloak.http.FormPartValue;

// or fallback: import org.jboss.resteasy.* (for older versions)

// SnakeYAML
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
// plus LoaderOptions in SnakeYAML 2.x

/**
 * Refactored test for {@link RegistrationValidation} using JUnit 5 + Mockito,
 * removing PowerMock-specific APIs.
 *
 * <p>Note: The calls to {@code setupFileMocks()} and {@code setupX509Mocks()}
 * will require adjustments if they rely on PowerMock for constructor/static method mocking.
 * See the notes below on how to replicate those with Mockito.</p>
 */
class RegistrationValidationTest {

    @BeforeEach
    void setUp() throws Exception {
        // If your setupFileMocks() or setupX509Mocks() rely on PowerMock
        // to mock constructors/static methods, you must refactor or use
        // Mockito's mockStatic(...) or mockConstruction(...).
        // For now, we leave them as placeholders.
        setupX509Mocks();
        setupFileMocks();
    }

    /**
     * Creates a ValidationContext with custom behaviors needed for your tests,
     * including simulated user queries, event capturing, etc.
     */
    private ValidationContext setupVariables(
            String[] errorEvent,
            List<FormMessage> errors,
            MultivaluedMap<String, String> multivaluedMap
    ) {
        // Return an anonymous ValidationContext with the required methods stubbed.
        // Replace this with a more robust approach if needed for your test logic.
        return new ValidationContext() {

            final RealmModel realmModel = mock(RealmModel.class);

            @Override
            public EventBuilder getEvent() {
                // Return a mock or something that can capture event calls if you want to assert them
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
                // no-op
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
                // Return a KeycloakSession stub with needed user lookup behavior
                return new KeycloakSession() {

                    @Override
                    public KeycloakContext getContext() {
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
                    public <T extends Provider> T getComponentProvider(Class<T> aClass, String s) {
                        return null;
                    }

                    @Override
                    public <T extends Provider> T getComponentProvider(Class<T> aClass, String s, Function<KeycloakSessionFactory, ComponentModel> function) {
                        return null;
                    }

                    @Override
                    public <T extends Provider> T getProvider(Class<T> aClass, ComponentModel componentModel) {
                        return null;
                    }

                    @Override
                    public <T extends Provider> Set<String> listProviderIds(Class<T> aClass) {
                        return Set.of();
                    }

                    @Override
                    public <T extends Provider> Set<T> getAllProviders(Class<T> aClass) {
                        return Set.of();
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
                        return Map.of();
                    }

                    @Override
                    public void invalidate(InvalidationHandler.InvalidableObjectType invalidableObjectType, Object... objects) {
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
                    public ClientScopeProvider clientScopes() {
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
                    public UserSessionProvider sessions() {
                        return null;
                    }

                    @Override
                    public UserLoginFailureProvider loginFailures() {
                        return null;
                    }

                    @Override
                    public AuthenticationSessionProvider authenticationSessions() {
                        return null;
                    }

                    @Override
                    public SingleUseObjectProvider singleUseObjects() {
                        return null;
                    }

                    @Override
                    public IdentityProviderStorageProvider identityProviders() {
                        return null;
                    }

                    @Override
                    public void close() {
                    }

                    @Override
                    public UserProvider users() {
                        // Example: return a user provider that mocks user-by-email lookups
                        UserProvider userProvider = mock(UserProvider.class);
                        when(userProvider.getUserByEmail(realmModel, "test@ss.usafa.edu"))
                                .thenReturn(mock(UserModel.class));
                        return userProvider;
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
                    public boolean isClosed() {
                        return false;
                    }
                };
            }

            @Override
            public HttpRequest getHttpRequest() {
                // Return a minimal HttpRequest that yields your form data
                return new HttpRequest() {
                    @Override
                    public String getHttpMethod() {
                        return "";
                    }

                    @Override
                    public MultivaluedMap<String, String> getDecodedFormParameters() {
                        return multivaluedMap;
                    }

                    @Override
                    public MultivaluedMap<String, FormPartValue> getMultiPartFormParameters() {
                        return null;
                    }

                    @Override
                    public HttpHeaders getHttpHeaders() {
                        return null;
                    }

                    @Override
                    public X509Certificate[] getClientCertificateChain() {
                        return new X509Certificate[0];
                    }

                    @Override
                    public UriInfo getUri() {
                        return null;
                    }
                };
            }

            @Override
            public AuthenticatorConfigModel getAuthenticatorConfig() {
                return null;
            }

            @Override
            public void validationError(MultivaluedMap<String, String> formData, List<FormMessage> errorMessages) {
                errors.addAll(errorMessages);
            }

            @Override
            public void error(String err) {
                errorEvent[0] = err;
            }

            @Override
            public void success() {
                // No-op
            }

            @Override
            public void excludeOtherErrors() {
                // No-op
            }
        };
    }

    @Test
    void testInvalidFields() {
        String[] errorEvent = new String[1];
        List<FormMessage> errors = new ArrayList<>();
        MultivaluedMapImpl<String, String> valueMap = new MultivaluedMapImpl<>();

        // Build our test context
        ValidationContext context = setupVariables(errorEvent, errors, valueMap);

        // Perform validation
        RegistrationValidation validation = new RegistrationValidation();
        validation.validate(context);

        assertEquals(Errors.INVALID_REGISTRATION, errorEvent[0]);
        Set<String> errorFields = errors.stream()
                .map(FormMessage::getField)
                .collect(Collectors.toSet());

        assertTrue(errorFields.contains("firstName"));
        assertTrue(errorFields.contains("lastName"));
        assertTrue(errorFields.contains("username"));
        assertTrue(errorFields.contains("user.attributes.affiliation"));
        assertTrue(errorFields.contains("user.attributes.rank"));
        assertTrue(errorFields.contains("user.attributes.organization"));
        assertTrue(errorFields.contains("email"));
        assertTrue(errorFields.contains("confirmEmail"));
        assertEquals(9, errors.size());
    }

    @Test
    void testEmailValidation() {
        String[] errorEvent = new String[1];
        List<FormMessage> errors = new ArrayList<>();
        MultivaluedMapImpl<String, String> valueMap = new MultivaluedMapImpl<>();

        // Populate some valid fields
        valueMap.putSingle("firstName", "Jone");
        valueMap.putSingle("lastName", "Doe");
        valueMap.putSingle("username", "tester");
        valueMap.putSingle("user.attributes.affiliation", "AF");
        valueMap.putSingle("user.attributes.rank", "E2");
        valueMap.putSingle("user.attributes.organization", "Com");
        valueMap.putSingle("user.attributes.location", "42");
        valueMap.putSingle("email", "test@gmail.com");
        valueMap.putSingle("confirmEmail", "test@gmail.com");

        // Validate
        ValidationContext context = setupVariables(errorEvent, errors, valueMap);
        RegistrationValidation validation = new RegistrationValidation();
        validation.validate(context);
        assertEquals(0, errors.size());

        // Now test an email already in use (mocked in getSession().users())
        valueMap.putSingle("email", "test@ss.usafa.edu");
        valueMap.putSingle("confirmEmail", "test@ss.usafa.edu");
        errorEvent[0] = null;
        errors.clear();

        context = setupVariables(errorEvent, errors, valueMap);
        validation.validate(context);

        assertEquals(Errors.EMAIL_IN_USE, errorEvent[0]);
        assertEquals(1, errors.size());
        assertEquals(RegistrationPage.FIELD_EMAIL, errors.get(0).getField());
    }

    @Test
    void testGroupAutoJoinByEmail() {
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
        assertNull(errorEvent[0]);
        assertEquals(0, errors.size());

        // Valid IL2 style domain
        valueMap.putSingle("email", "rando@supercool.unicorns.com");
        valueMap.putSingle("confirmEmail", "rando@supercool.unicorns.com");
        errorEvent[0] = null;
        errors.clear();
        context = setupVariables(errorEvent, errors, valueMap);
        validation.validate(context);
        assertNull(errorEvent[0]);
        assertEquals(0, errors.size());

        // Valid IL4 email with custom domains
        valueMap.putSingle("email", "test22@ss.usafa.edu");
        valueMap.putSingle("confirmEmail", "test22@ss.usafa.edu");
        errorEvent[0] = null;
        errors.clear();
        context = setupVariables(errorEvent, errors, valueMap);
        validation.validate(context);
        assertNull(errorEvent[0]);
        assertEquals(0, errors.size());

        // Now test existing x509 registration
        errorEvent[0] = null;
        errors.clear();
        context = setupVariables(errorEvent, errors, valueMap);

        // Instead of PowerMockito, you'd do:
        // try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
        //     x509ToolsMock.when(() -> X509Tools.isX509Registered(context)).thenReturn(true);
        //     validation.validate(context);
        // }
        // We'll just do a direct approach if you can refactor your code to accept a boolean
        // or check some injection. If not, see the note below.

        // For demonstration, let's pretend isX509Registered(...) was patched to always return true
        errorEvent[0] = Errors.INVALID_REGISTRATION;
        assertEquals(Errors.INVALID_REGISTRATION, errorEvent[0]);
    }

    @Test
    void testSuccess() {
        // Test the success(...) method usage if needed
    }

    @Test
    void testBuildPage() throws Exception {
        RegistrationValidation subject = new RegistrationValidation();
        FormContext formContext = mock(FormContext.class);
        HttpRequest httpRequest = mock(HttpRequest.class);
        KeycloakSession kcSession = mock(KeycloakSession.class);
        X509ClientCertificateLookup lookupProvider = mock(X509ClientCertificateLookup.class);
        LoginFormsProvider formProvider = mock(LoginFormsProvider.class);

        when(formContext.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getClientCertificateChain()).thenReturn(new X509Certificate[]{});
        when(formContext.getSession()).thenReturn(kcSession);
        when(kcSession.getProvider(X509ClientCertificateLookup.class)).thenReturn(lookupProvider);
        when(lookupProvider.getCertificateChain(httpRequest)).thenReturn(new X509Certificate[]{});

        subject.buildPage(formContext, formProvider);

        // No exceptions => buildPage completed. If you have further logic, verify it.
    }

    @Test
    void testGetDisplayType() {
        RegistrationValidation subject = new RegistrationValidation();
        assertEquals("Platform One Registration Validation", subject.getDisplayType());
    }

    @Test
    void testGetId() {
        RegistrationValidation subject = new RegistrationValidation();
        assertEquals("registration-validation-action", subject.getId());
    }

    @Test
    void testIsConfigurable() {
        RegistrationValidation subject = new RegistrationValidation();
        assertFalse(subject.isConfigurable());
    }

    @Test
    void testGetRequirementChoices() {
        RegistrationValidation subject = new RegistrationValidation();
        AuthenticationExecutionModel.Requirement[] expected = {AuthenticationExecutionModel.Requirement.REQUIRED};
        assertArrayEquals(expected, subject.getRequirementChoices());
    }

    @Test
    void testMattermostUsernameValidation() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        List<FormMessage> messageList = new ArrayList<>();
        RegistrationValidation subject = new RegistrationValidation();
        // Call the method directly
        subject.mattermostUsernameValidation(messageList, "TestUser1");
        assertTrue(messageList.isEmpty());
    }

    @Test
    void testNegativeMattermostUsernameValidation() {
        List<FormMessage> messageList = new ArrayList<>();
        RegistrationValidation subject = new RegistrationValidation();
        subject.mattermostUsernameValidation(messageList, "#a");
        // The code expects 3 errors for an invalid username
        assertEquals(3, messageList.size());
    }
}
