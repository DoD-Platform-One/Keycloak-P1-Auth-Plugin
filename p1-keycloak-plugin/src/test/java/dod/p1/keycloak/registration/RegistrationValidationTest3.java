package dod.p1.keycloak.registration;

import dod.p1.keycloak.common.CommonConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.validation.Validation;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Additional test coverage for {@link RegistrationValidation} class.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class RegistrationValidationTest3 {

    @Mock
    private ValidationContext validationContext;

    @Mock
    private FormContext formContext;

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmModel realm;

    @Mock
    private LoginFormsProvider loginFormsProvider;

    @Mock
    private HttpRequest httpRequest;

    @Mock
    private UserProvider userProvider;

    @Mock
    private UserModel userModel;

    @Mock
    private EventBuilder eventBuilder;

    @Mock
    private X509ClientCertificateLookup x509ClientCertificateLookup;

    private RegistrationValidation registrationValidation;

    @BeforeEach
    public void setUp() {
        registrationValidation = new RegistrationValidation();

        // Setup common mocks
        when(validationContext.getSession()).thenReturn(session);
        when(validationContext.getRealm()).thenReturn(realm);
        when(validationContext.getHttpRequest()).thenReturn(httpRequest);
        when(validationContext.getEvent()).thenReturn(eventBuilder);

        when(formContext.getSession()).thenReturn(session);
        when(formContext.getRealm()).thenReturn(realm);
        when(formContext.getHttpRequest()).thenReturn(httpRequest);
        when(formContext.getUser()).thenReturn(userModel);

        // Mock the UserProvider
        when(session.users()).thenReturn(userProvider);
        when(userProvider.getUserByEmail(any(RealmModel.class), anyString())).thenReturn(null);

        // Create an empty form data to avoid NPEs
        MultivaluedMap<String, String> emptyFormData = new MultivaluedHashMap<>();
        when(httpRequest.getDecodedFormParameters()).thenReturn(emptyFormData);
    }

    @Test
    public void testValidateWithValidData() {
        // Setup form data with all required fields
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(Validation.FIELD_USERNAME, "validuser");
        formData.add(RegistrationPage.FIELD_FIRST_NAME, "John");
        formData.add(RegistrationPage.FIELD_LAST_NAME, "Doe");
        formData.add(RegistrationPage.FIELD_EMAIL, "john.doe@example.com");
        formData.add("confirmEmail", "john.doe@example.com");
        formData.add("user.attributes.affiliation", "USAF");
        formData.add("user.attributes.rank", "E5");
        formData.add("user.attributes.organization", "Test Org");
        formData.add("user.attributes.location", "42"); // This is required to pass bot check

        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        // Mock success method to verify it's called
        doNothing().when(validationContext).success();

        // Call validate
        registrationValidation.validate(validationContext);

        // Verify success was called and no errors were added
        verify(validationContext).success();
        verify(validationContext, never()).error(anyString());
        verify(validationContext, never()).validationError(any(), any());
    }

    @Test
    public void testValidateWithInvalidLocation() {
        // Setup form data with invalid location (bot check)
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(Validation.FIELD_USERNAME, "validuser");
        formData.add(RegistrationPage.FIELD_FIRST_NAME, "John");
        formData.add(RegistrationPage.FIELD_LAST_NAME, "Doe");
        formData.add(RegistrationPage.FIELD_EMAIL, "john.doe@example.com");
        formData.add("confirmEmail", "john.doe@example.com");
        formData.add("user.attributes.affiliation", "USAF");
        formData.add("user.attributes.rank", "E5");
        formData.add("user.attributes.organization", "Test Org");
        formData.add("user.attributes.location", "invalid"); // Invalid location

        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        // Call validate
        registrationValidation.validate(validationContext);

        // Verify error was called
        verify(validationContext).error(Errors.INVALID_REGISTRATION);
        verify(validationContext).validationError(any(), any());
    }

    @Test
    public void testValidateWithX509AlreadyRegistered() {
        // Setup form data
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(Validation.FIELD_USERNAME, "validuser");
        formData.add(RegistrationPage.FIELD_FIRST_NAME, "John");
        formData.add(RegistrationPage.FIELD_LAST_NAME, "Doe");
        formData.add(RegistrationPage.FIELD_EMAIL, "john.doe@example.com");
        formData.add("confirmEmail", "john.doe@example.com");
        formData.add("user.attributes.affiliation", "USAF");
        formData.add("user.attributes.rank", "E5");
        formData.add("user.attributes.organization", "Test Org");
        formData.add("user.attributes.location", "42");

        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            // Mock X509Tools to return a username and indicate it's already registered
            x509ToolsMock.when(() -> X509Tools.getX509Username(validationContext)).thenReturn("x509-username@mil");
            x509ToolsMock.when(() -> X509Tools.isX509Registered(validationContext)).thenReturn(true);

            // Call validate
            registrationValidation.validate(validationContext);

            // Verify error was called with INVALID_REGISTRATION
            // Use atLeastOnce() since the method may be called multiple times
            verify(validationContext, atLeastOnce()).error(Errors.INVALID_REGISTRATION);
            verify(validationContext, atLeastOnce()).validationError(any(), any());
        }
    }

    @Test
    public void testValidateWithEmailMismatch() {
        // Setup form data with mismatched emails
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(Validation.FIELD_USERNAME, "validuser");
        formData.add(RegistrationPage.FIELD_FIRST_NAME, "John");
        formData.add(RegistrationPage.FIELD_LAST_NAME, "Doe");
        formData.add(RegistrationPage.FIELD_EMAIL, "john.doe@example.com");
        formData.add("confirmEmail", "different@example.com"); // Mismatched email
        formData.add("user.attributes.affiliation", "USAF");
        formData.add("user.attributes.rank", "E5");
        formData.add("user.attributes.organization", "Test Org");
        formData.add("user.attributes.location", "42");

        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        // Call validate
        registrationValidation.validate(validationContext);

        // Verify error was called
        verify(validationContext).error(Errors.INVALID_REGISTRATION);
        verify(validationContext).validationError(any(), any());
    }

    @Test
    public void testValidateWithInvalidEmail() {
        // Setup form data with invalid email
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(Validation.FIELD_USERNAME, "validuser");
        formData.add(RegistrationPage.FIELD_FIRST_NAME, "John");
        formData.add(RegistrationPage.FIELD_LAST_NAME, "Doe");
        formData.add(RegistrationPage.FIELD_EMAIL, "invalid-email"); // Invalid email
        formData.add("confirmEmail", "invalid-email");
        formData.add("user.attributes.affiliation", "USAF");
        formData.add("user.attributes.rank", "E5");
        formData.add("user.attributes.organization", "Test Org");
        formData.add("user.attributes.location", "42");

        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        // Call validate
        registrationValidation.validate(validationContext);

        // Verify error was called and event detail was set
        verify(validationContext).error(Errors.INVALID_REGISTRATION);
        verify(validationContext).validationError(any(), any());
        verify(eventBuilder).detail(eq(Details.EMAIL), eq("invalid-email"));
    }

    @Test
    public void testValidateWithEmailInUse() {
        // Setup form data
        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(Validation.FIELD_USERNAME, "validuser");
        formData.add(RegistrationPage.FIELD_FIRST_NAME, "John");
        formData.add(RegistrationPage.FIELD_LAST_NAME, "Doe");
        formData.add(RegistrationPage.FIELD_EMAIL, "existing@example.com");
        formData.add("confirmEmail", "existing@example.com");
        formData.add("user.attributes.affiliation", "USAF");
        formData.add("user.attributes.rank", "E5");
        formData.add("user.attributes.organization", "Test Org");
        formData.add("user.attributes.location", "42");

        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        // Mock that the email is already in use
        when(userProvider.getUserByEmail(realm, "existing@example.com")).thenReturn(mock(UserModel.class));

        // Call validate
        registrationValidation.validate(validationContext);

        // Verify error was called with EMAIL_IN_USE
        verify(validationContext).error(Errors.EMAIL_IN_USE);
        verify(validationContext).validationError(any(), any());
        verify(eventBuilder).detail(eq(Details.EMAIL), eq("existing@example.com"));
    }

    @Test
    public void testMattermostUsernameValidationWithEdgeCases() {
        List<FormMessage> errors = new ArrayList<>();

        // Test with username starting with a number
        registrationValidation.mattermostUsernameValidation(errors, "1username");
        assertEquals(1, errors.size());
        assertEquals(Validation.FIELD_USERNAME, errors.get(0).getField());
        errors.clear();

        // Test with username containing invalid characters
        registrationValidation.mattermostUsernameValidation(errors, "user@name");
        assertEquals(1, errors.size());
        assertEquals(Validation.FIELD_USERNAME, errors.get(0).getField());
        errors.clear();

        // Test with username that's too short
        registrationValidation.mattermostUsernameValidation(errors, "ab");
        assertEquals(1, errors.size());
        assertEquals(Validation.FIELD_USERNAME, errors.get(0).getField());
        errors.clear();

        // Test with username that's too long
        registrationValidation.mattermostUsernameValidation(errors, "test-username-that-is-way-too-long");
        assertEquals(1, errors.size());
        assertEquals(Validation.FIELD_USERNAME, errors.get(0).getField());
        errors.clear();

        // Test with valid username with mixed case and special characters
        registrationValidation.mattermostUsernameValidation(errors, "Valid-User_123");
        assertEquals(0, errors.size());
    }

    @Test
    public void testBuildFormFromX509WithComplexCertificate() throws Exception {
        // Setup
        X509Certificate cert = mock(X509Certificate.class);
        javax.security.auth.x500.X500Principal principal = new javax.security.auth.x500.X500Principal(
                "CN=DOE.JOHN.A.1234567890,OU=USAF,O=U.S. Government,C=US");
        when(cert.getSubjectX500Principal()).thenReturn(principal);

        X509Certificate[] certs = new X509Certificate[] { cert };

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(FormContext.class))).thenReturn("1234567890@mil");
            x509ToolsMock.when(() -> X509Tools.translateAffiliationShortName("USAF")).thenReturn("Air Force");

            // Call the method via reflection
            java.lang.reflect.Method method = RegistrationValidation.class.getDeclaredMethod(
                    "buildFormFromX509", FormContext.class, X509Certificate[].class);
            method.setAccessible(true);
            MultivaluedMap<String, String> result = (MultivaluedMap<String, String>) method.invoke(
                    registrationValidation, formContext, certs);

            // Verify form data was populated correctly
            assertEquals("1234567890@mil", result.getFirst("cacIdentity"));
            assertEquals("John", result.getFirst("firstName"));
            assertEquals("Doe", result.getFirst("lastName"));
            assertEquals("Air Force", result.getFirst("user.attributes.affiliation"));
        }
    }

    @Test
    public void testBuildFormFromX509WithUnusualCNFormat() throws Exception {
        // Setup with unusual CN format
        X509Certificate cert = mock(X509Certificate.class);
        javax.security.auth.x500.X500Principal principal = new javax.security.auth.x500.X500Principal(
                "CN=DOE-JOHN.1234567890,OU=USAF,O=U.S. Government,C=US");
        when(cert.getSubjectX500Principal()).thenReturn(principal);

        X509Certificate[] certs = new X509Certificate[] { cert };

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class)) {
            x509ToolsMock.when(() -> X509Tools.getX509Username(any(FormContext.class))).thenReturn("1234567890@mil");
            x509ToolsMock.when(() -> X509Tools.translateAffiliationShortName("USAF")).thenReturn("Air Force");

            // Call the method via reflection
            java.lang.reflect.Method method = RegistrationValidation.class.getDeclaredMethod(
                    "buildFormFromX509", FormContext.class, X509Certificate[].class);
            method.setAccessible(true);
            MultivaluedMap<String, String> result = (MultivaluedMap<String, String>) method.invoke(
                    registrationValidation, formContext, certs);

            // Verify cacIdentity was set but other fields might not be parsed correctly
            assertEquals("1234567890@mil", result.getFirst("cacIdentity"));
        }
    }

    @Test
    public void testSuccess() {
        // Setup
        when(formContext.getUser()).thenReturn(userModel);
        when(formContext.getRealm()).thenReturn(realm);
        when(formContext.getSession()).thenReturn(session);
        when(userModel.getEmail()).thenReturn("test@example.com");

        MultivaluedMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add(Validation.FIELD_EMAIL, "test@example.com");
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        try (MockedStatic<X509Tools> x509ToolsMock = mockStatic(X509Tools.class);
             MockedStatic<CommonConfig> commonConfigMock = mockStatic(CommonConfig.class)) {

            // Mock X509Tools
            x509ToolsMock.when(() -> X509Tools.getX509Username(formContext)).thenReturn("1234567890@mil");

            // Mock CommonConfig
            CommonConfig commonConfig = mock(CommonConfig.class);
            commonConfigMock.when(() -> CommonConfig.getInstance(session, realm)).thenReturn(commonConfig);
            when(commonConfig.getUserIdentityAttribute(realm)).thenReturn("usercertificate");
            when(commonConfig.getUserActive509Attribute()).thenReturn("activecac");

            // Call success
            registrationValidation.success(formContext);

            // Verify user attributes were set
            verify(userModel).setSingleAttribute(eq("mattermostid"), anyString());
            verify(userModel).setSingleAttribute(eq("usercertificate"), eq("1234567890@mil"));
            verify(userModel).setSingleAttribute(eq("activecac"), eq("1234567890@mil"));
            verify(userModel).addRequiredAction("TERMS_AND_CONDITIONS");
            verify(userModel, never()).setEmailVerified(true);
        }
    }
}
